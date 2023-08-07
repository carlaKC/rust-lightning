// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded paths and related utilities live here.

pub mod payment;
pub(crate) mod message;
pub(crate) mod utils;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::payment::BlindedPaymentTlvs;
use crate::offers::invoice::BlindedPayInfo;
use crate::ln::msgs::DecodeError;
use crate::sign::EntropySource;
use crate::util::ser::{Readable, Writeable, Writer};

use crate::io;
use crate::prelude::*;

/// Onion messages and payments can be sent and received to blinded paths, which serve to hide the
/// identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedPath {
	/// To send to a blinded path, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message or payment's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub introduction_node_id: PublicKey,
	/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
	/// message or payment.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub blinding_point: PublicKey,
	/// The hops composing the blinded path.
	pub blinded_hops: Vec<BlindedHop>,
}

/// An encrypted payload and node id corresponding to a hop in a payment or onion message path, to
/// be encoded in the sender's onion packet. These hops cannot be identified by outside observers
/// and thus can be used to hide the identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedHop {
	/// The blinded node id of this hop in a [`BlindedPath`].
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a [`BlindedPath`].
	// The node sending to this blinded path will later encode this payload into the onion packet for
	// this hop.
	pub encrypted_payload: Vec<u8>,
}

impl BlindedPath {
	/// Create a blinded path for an onion message, to be forwarded along `node_pks`. The last node
	/// pubkey in `node_pks` will be the destination node.
	///
	/// Errors if less than two hops are provided or if `node_pk`(s) are invalid.
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new_for_message<ES: EntropySource, T: secp256k1::Signing + secp256k1::Verification>
		(node_pks: &[PublicKey], entropy_source: &ES, secp_ctx: &Secp256k1<T>) -> Result<Self, ()>
	{
		if node_pks.len() < 2 { return Err(()) }
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let introduction_node_id = node_pks[0];

		Ok(BlindedPath {
			introduction_node_id,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: message::blinded_hops(secp_ctx, node_pks, &blinding_secret).map_err(|_| ())?,
		})
	}

	/// Create a blinded path for a payment, to be forwarded along `path`. The last node
	/// in `path` will be the destination node.
	///
	/// Errors if `path` is empty, a node id in `path` is invalid, or [`BlindedPayInfo`] calculation
	/// results in an integer overflow.
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new_for_payment<ES: EntropySource, T: secp256k1::Signing + secp256k1::Verification>(
		path: &[(PublicKey, BlindedPaymentTlvs)], entropy_source: &ES, secp_ctx: &Secp256k1<T>
	) -> Result<(BlindedPayInfo, Self), ()> {
		if path.len() < 1 { return Err(()) }
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		let blinded_payinfo = payment::compute_payinfo(path)?;
		Ok((blinded_payinfo, BlindedPath {
			introduction_node_id: path[0].0,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: payment::blinded_hops(secp_ctx, path, &blinding_secret).map_err(|_| ())?,
		}))
	}
}

impl Writeable for BlindedPath {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.introduction_node_id.write(w)?;
		self.blinding_point.write(w)?;
		(self.blinded_hops.len() as u8).write(w)?;
		for hop in &self.blinded_hops {
			hop.write(w)?;
		}
		Ok(())
	}
}

impl Readable for BlindedPath {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let introduction_node_id = Readable::read(r)?;
		let blinding_point = Readable::read(r)?;
		let num_hops: u8 = Readable::read(r)?;
		if num_hops == 0 { return Err(DecodeError::InvalidValue) }
		let mut blinded_hops: Vec<BlindedHop> = Vec::with_capacity(num_hops.into());
		for _ in 0..num_hops {
			blinded_hops.push(Readable::read(r)?);
		}
		Ok(BlindedPath {
			introduction_node_id,
			blinding_point,
			blinded_hops,
		})
	}
}

impl_writeable!(BlindedHop, {
	blinded_node_id,
	encrypted_payload
});

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The node id of the next hop in the onion message's path.
	pub(super) next_node_id: PublicKey,
	/// Senders to a blinded path use this value to concatenate the route they find to the
	/// introduction node with the blinded path.
	pub(super) next_blinding_override: Option<PublicKey>,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
pub(crate) struct ReceiveTlvs {
	/// If `path_id` is `Some`, it is used to identify the blinded path that this onion message is
	/// sending to. This is useful for receivers to check that said blinded path is being used in
	/// the right context.
	pub(super) path_id: Option<[u8; 32]>,
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(4, self.next_node_id, required),
			(8, self.next_blinding_override, option)
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(6, self.path_id, option),
		});
		Ok(())
	}
}

#[cfg(test)]
mod test;
