// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK sends, receives, and forwards onion messages via the [`OnionMessenger`]. See its docs for
//! more information.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::blinded_path::{BlindedPath, ForwardTlvs, ReceiveTlvs, utils};
use crate::sign::{EntropySource, KeysManager, NodeSigner, Recipient};
use crate::events::OnionMessageProvider;
use crate::ln::features::{InitFeatures, NodeFeatures};
use crate::ln::msgs::{self, OnionMessageHandler};
use crate::ln::onion_utils;
use crate::ln::peer_handler::IgnoringMessageHandler;
pub use super::packet::{CustomOnionMessageContents, OnionMessageContents};
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use crate::util::logger::Logger;
use crate::util::ser::Writeable;

use core::ops::Deref;
use crate::io;
use crate::sync::{Arc, Mutex};
use crate::prelude::*;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers]. Currently, only sending
/// and receiving custom onion messages is supported.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::blinded_path::BlindedPath;
/// # use lightning::sign::KeysManager;
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::{CustomOnionMessageContents, Destination, OnionMessageContents, OnionMessenger};
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let (hop_node_id2, hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1, hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// # let your_custom_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(&keys_manager, &keys_manager, logger, &your_custom_message_handler);
///
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// 	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// 		# Ok(())
/// 		// Write your custom onion message to `w`
/// 	}
/// }
/// impl CustomOnionMessageContents for YourCustomMessage {
/// 	fn tlv_type(&self) -> u64 {
/// 		# let your_custom_message_type = 42;
/// 		your_custom_message_type
/// 	}
/// }
/// // Send a custom onion message to a node id.
/// let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::Node(destination_node_id), message, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_path = BlindedPath::new_for_message(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// # let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::BlindedPath(blinded_path), message, reply_path);
/// ```
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
pub struct OnionMessenger<ES: Deref, NS: Deref, L: Deref, CMH: Deref>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH:: Target: CustomOnionMessageHandler,
{
	entropy_source: ES,
	node_signer: NS,
	logger: L,
	pending_messages: Mutex<HashMap<PublicKey, VecDeque<msgs::OnionMessage>>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	custom_handler: CMH,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
}

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded path.
	BlindedPath(BlindedPath),
}

impl Destination {
	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedPath(BlindedPath { blinded_hops, .. }) => blinded_hops.len(),
		}
	}
}

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [`Destination`] was an invalid [`BlindedPath`], due to having fewer than two
	/// blinded hops.
	TooFewBlindedHops,
	/// Our next-hop peer was offline or does not support onion message forwarding.
	InvalidFirstHop,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
	GetNodeIdFailed,
	/// We attempted to send to a blinded path where we are the introduction node, and failed to
	/// advance the blinded path to make the second hop the new introduction node. Either
	/// [`NodeSigner::ecdh`] failed, we failed to tweak the current blinding point to get the
	/// new blinding point, or we were attempting to send to ourselves.
	BlindedPathAdvanceFailed,
}

/// Handler for custom onion messages. If you are using [`SimpleArcOnionMessenger`],
/// [`SimpleRefOnionMessenger`], or prefer to ignore inbound custom onion messages,
/// [`IgnoringMessageHandler`] must be provided to [`OnionMessenger::new`]. Otherwise, a custom
/// implementation of this trait must be provided, with [`CustomMessage`] specifying the supported
/// message types.
///
/// See [`OnionMessenger`] for example usage.
///
/// [`IgnoringMessageHandler`]: crate::ln::peer_handler::IgnoringMessageHandler
/// [`CustomMessage`]: Self::CustomMessage
pub trait CustomOnionMessageHandler {
	/// The message known to the handler. To support multiple message types, you may want to make this
	/// an enum with a variant for each supported message.
	type CustomMessage: CustomOnionMessageContents;
	/// Called with the custom message that was received.
	fn handle_custom_message(&self, msg: Self::CustomMessage);
	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	fn read_custom_message<R: io::Read>(&self, message_type: u64, buffer: &mut R) -> Result<Option<Self::CustomMessage>, msgs::DecodeError>;
}

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(entropy_source: ES, node_signer: NS, logger: L, custom_handler: CMH) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		OnionMessenger {
			entropy_source,
			node_signer,
			pending_messages: Mutex::new(HashMap::new()),
			secp_ctx,
			logger,
			custom_handler,
		}
	}

	/// Send an onion message with contents `message` to `destination`, routing it through `intermediate_nodes`.
	/// See [`OnionMessenger`] for example usage.
	pub fn send_onion_message<T: CustomOnionMessageContents>(&self, intermediate_nodes: &[PublicKey], mut destination: Destination, message: OnionMessageContents<T>, reply_path: Option<BlindedPath>) -> Result<(), SendError> {
		log_info!(self.logger, "Sending onion message via: {:?}", intermediate_nodes);
		if let Destination::BlindedPath(BlindedPath { ref blinded_hops, .. }) = destination {
			if blinded_hops.len() < 2 {
				return Err(SendError::TooFewBlindedHops);
			}
		}
		let OnionMessageContents::Custom(ref msg) = message;
		if msg.tlv_type() < 64 { return Err(SendError::InvalidMessage) }

		// If we are sending straight to a blinded path and we are the introduction node, we need to
		// advance the blinded path by 1 hop so the second hop is the new introduction node.
		if intermediate_nodes.len() == 0 {
			if let Destination::BlindedPath(ref mut blinded_path) = destination {
				let our_node_id = self.node_signer.get_node_id(Recipient::Node)
					.map_err(|()| SendError::GetNodeIdFailed)?;
				if blinded_path.introduction_node_id == our_node_id {
					blinded_path.advance_message_path_by_one(&self.node_signer, &self.secp_ctx)
						.map_err(|()| SendError::BlindedPathAdvanceFailed)?;
				}
			}
		}

		let blinding_secret_bytes = self.entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		log_info!(self.logger, "Blinding secret on send is: {}", hex::encode(blinding_secret_bytes));

		let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
			(intermediate_nodes[0], PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret))
		} else {
			match destination {
				Destination::Node(pk) => (pk, PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret)),
				Destination::BlindedPath(BlindedPath { introduction_node_id, blinding_point, .. }) =>
					(introduction_node_id, blinding_point),
			}
		};
		let (packet_payloads, packet_keys) = packet_payloads_and_keys(
			&self.secp_ctx, intermediate_nodes, destination, message, reply_path, &blinding_secret)
			.map_err(|e| SendError::Secp256k1(e))?;

		let prng_seed = self.entropy_source.get_secure_random_bytes();


		log_info!(self.logger, "Session key is {}", hex::encode(prng_seed));
		let onion_routing_packet = construct_onion_message_packet(
			packet_payloads, packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

		let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
		if outbound_buffer_full(&introduction_node_id, &pending_per_peer_msgs) { return Err(SendError::BufferFull) }
		log_info!(self.logger,"Adding message to pending set");
		match pending_per_peer_msgs.entry(introduction_node_id) {
			hash_map::Entry::Vacant(_) => Err(SendError::InvalidFirstHop),
			hash_map::Entry::Occupied(mut e) => {
				log_info!(self.logger, "Sending onion message to {introduction_node_id}");
				e.get_mut().push_back(msgs::OnionMessage { blinding_point, onion_routing_packet });
				Ok(())
			}
		}
	}

	#[cfg(test)]
	pub(super) fn release_pending_msgs(&self) -> HashMap<PublicKey, VecDeque<msgs::OnionMessage>> {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		let mut msgs = HashMap::new();
		// We don't want to disconnect the peers by removing them entirely from the original map, so we
		// swap the pending message buffers individually.
		for (peer_node_id, pending_messages) in &mut *pending_msgs {
			msgs.insert(*peer_node_id, core::mem::take(pending_messages));
		}
		msgs
	}
}

fn outbound_buffer_full(peer_node_id: &PublicKey, buffer: &HashMap<PublicKey, VecDeque<msgs::OnionMessage>>) -> bool {
	const MAX_TOTAL_BUFFER_SIZE: usize = (1 << 20) * 128;
	const MAX_PER_PEER_BUFFER_SIZE: usize = (1 << 10) * 256;
	let mut total_buffered_bytes = 0;
	let mut peer_buffered_bytes = 0;
	for (pk, peer_buf) in buffer {
		for om in peer_buf {
			let om_len = om.serialized_length();
			if pk == peer_node_id {
				peer_buffered_bytes += om_len;
			}
			total_buffered_bytes += om_len;

			if total_buffered_bytes >= MAX_TOTAL_BUFFER_SIZE ||
				peer_buffered_bytes >= MAX_PER_PEER_BUFFER_SIZE
			{
				return true
			}
		}
	}
	false
}

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessageHandler for OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler + Sized,
{
	/// Handle an incoming onion message. Currently, if a message was destined for us we will log, but
	/// soon we'll delegate the onion message to a handler that can generate invoices or send
	/// payments.
	fn handle_onion_message(&self, peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		log_info!(self.logger,"Handling onion message from {peer_node_id}");
		let control_tlvs_ss = match self.node_signer.ecdh(Recipient::Node, &msg.blinding_point, None) {
			Ok(ss) => ss,
			Err(e) =>  {
				log_error!(self.logger, "Failed to retrieve node secret: {:?}", e);
				return
			}
		};
		let onion_decode_ss = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(control_tlvs_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			match self.node_signer.ecdh(Recipient::Node, &msg.onion_routing_packet.public_key,
				Some(&Scalar::from_be_bytes(blinding_factor).unwrap()))
			{
				Ok(ss) => ss.secret_bytes(),
				Err(()) => {
					log_trace!(self.logger, "Failed to compute onion packet shared secret");
					return
				}
			}
		};
		match onion_utils::decode_next_untagged_hop(onion_decode_ss, &msg.onion_routing_packet.hop_data[..],
			msg.onion_routing_packet.hmac, (control_tlvs_ss, &*self.custom_handler))
		{
			Ok((Payload::Receive::<<<CMH as Deref>::Target as CustomOnionMessageHandler>::CustomMessage> {
				message, control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id }), reply_path,
			}, None)) => {
				log_info!(self.logger,
					"Received an onion message with path_id {:02x?} and {} reply_path",
						path_id, if reply_path.is_some() { "a" } else { "no" });
				match message {
					OnionMessageContents::Custom(msg) => self.custom_handler.handle_custom_message(msg),
				}
			},
			Ok((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
				next_node_id, next_blinding_override
			})), Some((next_hop_hmac, new_packet_bytes)))) => {
				// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
				// blinded hop and this onion message is destined for us. In this situation, we should keep
				// unwrapping the onion layers to get to the final payload. Since we don't have the option
				// of creating blinded paths with dummy hops currently, we should be ok to not handle this
				// for now.
				let new_pubkey = match onion_utils::next_hop_packet_pubkey(&self.secp_ctx, msg.onion_routing_packet.public_key, &onion_decode_ss) {
					Ok(pk) => pk,
					Err(e) => {
						log_trace!(self.logger, "Failed to compute next hop packet pubkey: {}", e);
						return
					}
				};
				let outgoing_packet = Packet {
					version: 0,
					public_key: new_pubkey,
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac,
				};
				let onion_message = msgs::OnionMessage {
					blinding_point: match next_blinding_override {
						Some(blinding_point) => blinding_point,
						None => {
							let blinding_factor = {
								let mut sha = Sha256::engine();
								sha.input(&msg.blinding_point.serialize()[..]);
								sha.input(control_tlvs_ss.as_ref());
								Sha256::from_engine(sha).into_inner()
							};
							let next_blinding_point = msg.blinding_point;
							match next_blinding_point.mul_tweak(&self.secp_ctx, &Scalar::from_be_bytes(blinding_factor).unwrap()) {
								Ok(bp) => bp,
								Err(e) => {
									log_trace!(self.logger, "Failed to compute next blinding point: {}", e);
									return
								}
							}
						},
					},
					onion_routing_packet: outgoing_packet,
				};

				log_info!(self.logger, "Next node for onion message is: {next_node_id}");
				let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
				if outbound_buffer_full(&next_node_id, &pending_per_peer_msgs) {
					log_trace!(self.logger, "Dropping forwarded onion message to peer {:?}: outbound buffer full", next_node_id);
					return
				}

				for key in pending_per_peer_msgs.keys() {
					let item = pending_per_peer_msgs.get(key).unwrap().len();
					log_info!(self.logger, "Key: {}, len: {}", key, item);
				}

				#[cfg(fuzzing)]
				pending_per_peer_msgs.entry(next_node_id).or_insert_with(VecDeque::new);
				match pending_per_peer_msgs.entry(next_node_id) {
					hash_map::Entry::Vacant(_) => {
						log_trace!(self.logger, "Dropping forwarded onion message to disconnected peer {next_node_id}");
						return
					},
					hash_map::Entry::Occupied(mut e) => {
						e.get_mut().push_back(onion_message);
						log_trace!(self.logger, "Forwarding an onion message to peer {}", next_node_id);
					}
				};
			},
			Err(e) => {
				log_trace!(self.logger, "Errored decoding onion message packet: {:?}", e);
			},
			_ => {
				log_trace!(self.logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			},
		};
	}

	fn peer_connected(&self, their_node_id: &PublicKey, init: &msgs::Init, _inbound: bool) -> Result<(), ()> {
		if init.features.supports_onion_messages() {
			let mut peers = self.pending_messages.lock().unwrap();
			peers.insert(their_node_id.clone(), VecDeque::new());
		}
		Ok(())
	}

	fn peer_disconnected(&self, their_node_id: &PublicKey) {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		pending_msgs.remove(their_node_id);
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_onion_messages_optional();
		features
	}

	fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		features
	}
}

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessageProvider for OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler,
{
	fn next_onion_message_for_peer(&self, peer_node_id: PublicKey) -> Option<msgs::OnionMessage> {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		log_info!(self.logger,"Looking for next onion message for: {peer_node_id}");

		for k in pending_msgs.keys() {
			log_info!(self.logger,"Pending messages: {k}");
		}

		if let Some(msgs) = pending_msgs.get_mut(&peer_node_id) {

			let m = msgs.pop_front();
			log_info!(self.logger,"Got a message for {peer_node_id}: {:?}", m);
			return m
		}
		None
	}
}

// TODO: parameterize the below Simple* types with OnionMessenger and handle the messages it
// produces
/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
///
/// This is not exported to bindings users as `Arc`s don't make sense in bindings.
///
/// [`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
/// [`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
pub type SimpleArcOnionMessenger<L> = OnionMessenger<Arc<KeysManager>, Arc<KeysManager>, Arc<L>, IgnoringMessageHandler>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
/// This is not exported to bindings users as general type aliases don't make sense in bindings.
///
/// [`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
/// [`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<&'a KeysManager, &'a KeysManager, &'b L, IgnoringMessageHandler>;

/// Construct onion packet payloads and keys for sending an onion message along the given
/// `unblinded_path` to the given `destination`.
fn packet_payloads_and_keys<T: CustomOnionMessageContents, S: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<S>, unblinded_path: &[PublicKey], destination: Destination,
	message: OnionMessageContents<T>, mut reply_path: Option<BlindedPath>, session_priv: &SecretKey
) -> Result<(Vec<(Payload<T>, [u8; 32])>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut payloads = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	let (mut intro_node_id_blinding_pt, num_blinded_hops) = if let Destination::BlindedPath(BlindedPath {
		introduction_node_id, blinding_point, blinded_hops }) = &destination {
		(Some((*introduction_node_id, *blinding_point)), blinded_hops.len()) } else { (None, 0) };
	let num_unblinded_hops = num_hops - num_blinded_hops;

	let mut unblinded_path_idx = 0;
	let mut blinded_path_idx = 0;
	let mut prev_control_tlvs_ss = None;
	let mut final_control_tlvs = None;
	utils::construct_keys_callback(secp_ctx, unblinded_path, Some(destination), session_priv, |_, onion_packet_ss, ephemeral_pubkey, control_tlvs_ss, unblinded_pk_opt, enc_payload_opt| {
		if num_unblinded_hops != 0 && unblinded_path_idx < num_unblinded_hops {
			if let Some(ss) = prev_control_tlvs_ss.take() {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
					ForwardTlvs {
						next_node_id: unblinded_pk_opt.unwrap(),
						next_blinding_override: None,
					}
				)), ss));
			}
			prev_control_tlvs_ss = Some(control_tlvs_ss);
			unblinded_path_idx += 1;
		} else if let Some((intro_node_id, blinding_pt)) = intro_node_id_blinding_pt.take() {
			if let Some(control_tlvs_ss) = prev_control_tlvs_ss.take() {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
					next_node_id: intro_node_id,
					next_blinding_override: Some(blinding_pt),
				})), control_tlvs_ss));
			}
		}
		if blinded_path_idx < num_blinded_hops.saturating_sub(1) && enc_payload_opt.is_some() {
			payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(enc_payload_opt.unwrap())),
				control_tlvs_ss));
			blinded_path_idx += 1;
		} else if let Some(encrypted_payload) = enc_payload_opt {
			final_control_tlvs = Some(ReceiveControlTlvs::Blinded(encrypted_payload));
			prev_control_tlvs_ss = Some(control_tlvs_ss);
		}

		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(onion_packet_ss.as_ref());
		onion_packet_keys.push(onion_utils::OnionKeys {
			#[cfg(test)]
			shared_secret: onion_packet_ss,
			#[cfg(test)]
			blinding_factor: [0; 32],
			ephemeral_pubkey,
			rho,
			mu,
		});
	})?;

	if let Some(control_tlvs) = final_control_tlvs {
		payloads.push((Payload::Receive {
			control_tlvs,
			reply_path: reply_path.take(),
			message,
		}, prev_control_tlvs_ss.unwrap()));
	} else {
		payloads.push((Payload::Receive {
			control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id: None, }),
			reply_path: reply_path.take(),
			message,
		}, prev_control_tlvs_ss.unwrap()));
	}

	Ok((payloads, onion_packet_keys))
}

/// Errors if the serialized payload size exceeds onion_message::BIG_PACKET_HOP_DATA_LEN
fn construct_onion_message_packet<T: CustomOnionMessageContents>(payloads: Vec<(Payload<T>, [u8; 32])>, onion_keys: Vec<onion_utils::OnionKeys>, prng_seed: [u8; 32]) -> Result<Packet, ()> {
	// Spec rationale:
	// "`len` allows larger messages to be sent than the standard 1300 bytes allowed for an HTLC
	// onion, but this should be used sparingly as it is reduces anonymity set, hence the
	// recommendation that it either look like an HTLC onion, or if larger, be a fixed size."
	let payloads_ser_len = onion_utils::payloads_serialized_length(&payloads);
	let hop_data_len = if payloads_ser_len <= SMALL_PACKET_HOP_DATA_LEN {
		SMALL_PACKET_HOP_DATA_LEN
	} else if payloads_ser_len <= BIG_PACKET_HOP_DATA_LEN {
		BIG_PACKET_HOP_DATA_LEN
	} else { return Err(()) };

	onion_utils::construct_onion_message_packet::<_, _>(
		payloads, onion_keys, prng_seed, hop_data_len)
}


mod test {
	use crate::util::ser::Writeable;
	use crate::ln::features::InitFeatures;
	use crate::ln::msgs::{OnionMessageHandler, Init};
	use crate::ln::peer_handler::IgnoringMessageHandler;
	use crate::util::test_utils::{TestLogger, TestNodeSigner};
	use crate::sign::EntropySource;
	use crate::onion_message::{OnionMessenger, CustomOnionMessageHandler, Destination};
	use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
	use core::str::FromStr;
	use crate::onion_message::OnionMessageContents;
	use super::CustomOnionMessageContents;
	use crate::events::OnionMessageProvider;
	use crate::blinded_path::{BlindedPath, BlindedHop};
	use core::cell::RefCell;

	// DeterministicEntropy implements the entropy source trait to return deterministic entropy tests. It takes a
	// vector of values to return, and will index by call count to get the return value for each invocation.
	struct DeterministicEntropy {
		call_count: RefCell<usize>,
		set_entropy: Vec<[u8; 32]>,
	}

	impl DeterministicEntropy {
		fn new(set_entropy: Vec<[u8; 32]>) -> Self {
			DeterministicEntropy { call_count: RefCell::new(0), set_entropy }
		}
	}

	impl EntropySource for DeterministicEntropy {
		/// Implements fixed entropy for deterministic tests.
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let mut call_count = self.call_count.borrow_mut();
			let r = self.set_entropy[*call_count];
			*call_count+=1;
			r
		}
    }

	struct CustomMessage {}

	impl CustomOnionMessageContents for CustomMessage {
    	fn tlv_type(&self) -> u64 {
        	601
    	}
	}

	impl_writeable!(CustomMessage, {});

	#[test]
	/// Tests sending an onion message to a blinded path, as provided in bolt-04 test vectors. In this test, Alice
	/// sends an onion message to a blinded path with Bob as an introduction node, followed by blinded hops to Carol
	/// and Dave.
	fn test_onion_message_vectors () {
		let secp_ctx = Secp256k1::new();

		// Create the blinding point that Alice will use to send her onion message.
		let blinding_point = PublicKey::from_str("031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99").unwrap();

		// Setup node ids for each hop in the route and sanity check that the derived pubkey matches the string
		// provided in the test vectors where appropriate. We make up a sneder privkey/pubkey pair because we need to
		// have an origin point.
		let sender_privkey = SecretKey::from_str("4241414141414141414141414141414141414141414141414141414141414141").unwrap();
		let sender_pubkey = sender_privkey.public_key(&secp_ctx);

		let alice_privkey = SecretKey::from_str("4141414141414141414141414141414141414141414141414141414141414141").unwrap();
		let alice_pubkey = alice_privkey.public_key(&secp_ctx);

		let bob_privkey = SecretKey::from_str("4242424242424242424242424242424242424242424242424242424242424242").unwrap();
		let bob_pubkey = bob_privkey.public_key(&secp_ctx);
		let bob_pubkey_vec = PublicKey::from_str("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap();
		assert_eq!(bob_pubkey_vec, bob_pubkey);

		let carol_privkey = SecretKey::from_str("4343434343434343434343434343434343434343434343434343434343434343").unwrap();
		let carol_pubkey = carol_privkey.public_key(&secp_ctx);
		let carol_pubkey_vec = PublicKey::from_str("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap();
		assert_eq!(carol_pubkey_vec, carol_pubkey);

		let dave_privkey = SecretKey::from_str("4444444444444444444444444444444444444444444444444444444444444444").unwrap();
		let dave_pubkey = dave_privkey.public_key(&secp_ctx);
		let dave_pubkey_vec = PublicKey::from_str("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap();
		assert_eq!(dave_pubkey_vec, dave_pubkey);

		// Create blinded node IDs and encrypted payloads for Carol and Dave's blinded hops.
		let blinded_alice_id = PublicKey::from_str("02d1c3d73f8cac67e7c5b6ec517282d5ba0a52b06a29ec92ff01e12decf76003c1").unwrap();
		let encrypted_data_alice = hex::decode("49531cf38d3280b7f4af6d6461a2b32e3df50acfd35176fc61422a1096eed4dfc3806f29bf74320f712a61c766e7f7caac0c42f86040125fbaeec0c7613202b206dbdd31fda56394367b66a711bfd7d5bedbe20bed1b").unwrap();

		let blinded_bob_id = PublicKey::from_str("03f1465ca5cf3ec83f16f9343d02e6c24b76993a93e1dea2398f3147a9be893d7a").unwrap();
		let encrypted_bob_data = hex::decode("adf6771d3983b7f543d1b3d7a12b440b2bd3e1b3b8d6ec1023f6dec4f0e7548a6f57f6dbe9573b0a0f24f7c5773a7dd7a7bdb6bd0ee686d759f5").unwrap();

		let blinded_carol_id = PublicKey::from_str("035dbc0493aa4e7eea369d6a06e8013fd03e66a5eea91c455ed65950c4942b624b").unwrap();
		let encrypted_carol_data = hex::decode("d8903df7a79ac799a0b59f4ba22f6a599fa32e7ff1a8325fc22b88d278ce3e4840af02adfb82d6145a189ba50c2219c9e4351e634d198e0849ac").unwrap();

		let blinded_dave_id = PublicKey::from_str("0237bf019fa0fbecde8b4a1c7b197c9c1c76f9a23d67dd55bb5e42e1f50bb771a6").unwrap();
		let encrypted_dave_data = hex::decode("bdc03f088764c6224c8f939e321bf096f363b2092db381fc8787f891c8e6dc9284991b98d2a63d9f91fe563065366dd406cd8e112cdaaa80d0e6").unwrap();

		// Next, create a blinded path with Bob as the introduction point, followed by Carol and Bob as blinded hops.
		let blinded_path = BlindedPath{
			introduction_node_id: alice_pubkey,
			blinding_point,
			blinded_hops: vec![
				BlindedHop {
					blinded_node_id: blinded_alice_id,
					encrypted_payload: encrypted_data_alice,
				},
				BlindedHop {
					blinded_node_id: blinded_bob_id,
					encrypted_payload: encrypted_bob_data,
				},
				BlindedHop {
					blinded_node_id: blinded_carol_id,
					encrypted_payload: encrypted_carol_data,
				},
				BlindedHop {
					blinded_node_id: blinded_dave_id,
					encrypted_payload: encrypted_dave_data,
				},
			],
		};

		// Setup onion messengers for each hop in the route to pass along onion messages.
		let blinding_secret_bytes = hex::decode("6363636363636363636363636363636363636363636363636363636363636363").unwrap();
		let mut blinding_secret = [0;32];
		blinding_secret.copy_from_slice(&blinding_secret_bytes);

		let session_key_bytes = hex::decode("0303030303030303030303030303030303030303030303030303030303030303").unwrap();
		let mut session_key = [0; 32];
		session_key.copy_from_slice(&session_key_bytes);

		// Alice's onion creation will first generate a blinding secret then a session key when it comes time to
		// create the onion message, so we setup our test to return them in order. The onion messenger itself makes
		// one call to our entropy source on creation, so each entropy source is created with one "no-op" entropy
		// value.
		/*let sender_entropy =  &DeterministicEntropy::new(vec![[0;32], blinding_secret, session_key]);
		let sender_signer = &TestNodeSigner::new(sender_privkey);
		let sender_logger = &TestLogger::new();

		let sender_messenger = OnionMessenger::new(
			sender_entropy,
			sender_signer,
			sender_logger,
			&IgnoringMessageHandler{},
		);*/

		let alice_entropy = &DeterministicEntropy::new(vec![[0;32], blinding_secret, session_key]);
		let alice_signer = &TestNodeSigner::new(alice_privkey);
		let alice_logger = &TestLogger::new();

		let alice_messenger = OnionMessenger::new(
			alice_entropy,
			alice_signer,
			alice_logger,
			&IgnoringMessageHandler{},
		);

		let bob_entropy =&DeterministicEntropy::new(vec![ [0;32] ]);
		let bob_signer = &TestNodeSigner::new(bob_privkey);
		let bob_logger = &TestLogger::new();

		let bob_messenger = OnionMessenger::new(
			bob_entropy,
			bob_signer,
			bob_logger,
			&IgnoringMessageHandler{},
		);

		let carol_entropy = &DeterministicEntropy::new(vec![ [0;32] ]);
		let carol_signer = &TestNodeSigner::new(carol_privkey);
		let carol_logger = &TestLogger::new();

		let carol_messenger = OnionMessenger::new(
			carol_entropy,
			carol_signer,
			carol_logger,
			&IgnoringMessageHandler{},
		);

		let dave_entropy = &DeterministicEntropy::new(vec![ [0;32]]);
		let dave_signer =  &TestNodeSigner::new(dave_privkey);
		let dave_logger = &TestLogger::new();

		let dave_messenger = OnionMessenger::new(
			dave_entropy,
			dave_signer,
			dave_logger,
			&IgnoringMessageHandler{}, // TODO: AssertingMessageHandler that handles custom
									   // messages and asserts that the thing that comes out the
									   // end
		);

		// Notify the next peer as online and supporting onion messages for each hop so that onion messages will be
		// relayed onwards.
		let onion_message_optional: u64 = 1 << 39 ;// TODO: import feature ONION_MESSAGES_OPTIONAL;
		let init = &Init {
			features: InitFeatures::from_le_bytes(onion_message_optional.to_le_bytes().to_vec()),
			remote_network_address: None,
		};

		//assert!(sender_messenger.peer_connected(&alice_pubkey, &init, true).is_ok());
		assert!(alice_messenger.peer_connected(&bob_pubkey, &init, true).is_ok());
		assert!(bob_messenger.peer_connected(&carol_pubkey, &init, true).is_ok());
		assert!(carol_messenger.peer_connected(&dave_pubkey, &init, true).is_ok());

		// Instruct the sender to send an onion message to the blinded path with an intermediate hop to Alice to reach
		// the introduction node (Bob).
		alice_messenger.send_onion_message(
			&[],
			Destination::BlindedPath(blinded_path),
			OnionMessageContents::Custom(CustomMessage{}), // Needs to have some payload for Dave
			None,
		).unwrap();


		// expecting in the test vectors.
		let expected_message = hex::decode("0201031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd9905560002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb").unwrap();
		let alice_bob_message = alice_messenger.next_onion_message_for_peer(bob_pubkey).unwrap();
		let mut w = Vec::with_capacity(expected_message.len());
		assert!(alice_bob_message.write(&mut w).is_ok());

		//assert_eq!(expected_message, w);

		//alice_messenger.handle_onion_message(&sender_pubkey, &msg);
		//let alice_bob_message = alice_messenger.next_onion_message_for_peer(bob_pubkey).unwrap();

		// Pass the message on to Bob's onion messenger.
		bob_messenger.handle_onion_message(&alice_pubkey, &alice_bob_message);

		// Bob should queue an outgoing message for carol
		let bob_carol_message = bob_messenger.next_onion_message_for_peer(carol_pubkey).unwrap();

		// Pass the message along to Carol's onion messenger.
		carol_messenger.handle_onion_message(&bob_pubkey, &bob_carol_message);

		// Carol should queue an outgoing message for dave.
		let carol_dave_message = carol_messenger.next_onion_message_for_peer(dave_pubkey).unwrap();

		// Finally, pass the message along to Dave's onion messenger.
		dave_messenger.handle_onion_message(&carol_pubkey, &carol_dave_message);
	}
}
