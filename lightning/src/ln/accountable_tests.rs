// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for verifying the correct relay of accountable signals between nodes.

use crate::ln::channelmanager::{HTLCForwardInfo, PaymentId, PendingAddHTLCInfo, PendingHTLCInfo};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::onion_utils;
use crate::ln::outbound_payment::{RecipientOnionFields, Retry};
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::sign::EntropySource;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

fn test_accountable_forwarding_with_override(
	override_accountable: Option<bool>, expected_forwarded: bool,
) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_ab = create_announced_chan_between_nodes(&nodes, 0, 1);
	let _chan_bc = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], None, None);
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV),
		100_000,
	);
	let onion_fields = RecipientOnionFields::secret_only(payment_secret, 100_000);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment(payment_hash, onion_fields, payment_id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let updates_ab = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	assert_eq!(updates_ab.update_add_htlcs.len(), 1);
	let mut htlc_ab = updates_ab.update_add_htlcs[0].clone();
	assert_eq!(htlc_ab.accountable, Some(false));

	// Override accountable value if requested
	if let Some(override_value) = override_accountable {
		htlc_ab.accountable = Some(override_value);
	}

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &htlc_ab);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates_ab.commitment_signed, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let updates_bc = get_htlc_update_msgs(&nodes[1], &nodes[2].node.get_our_node_id());
	assert_eq!(updates_bc.update_add_htlcs.len(), 1);
	let htlc_bc = &updates_bc.update_add_htlcs[0];
	assert_eq!(
		htlc_bc.accountable,
		Some(expected_forwarded),
		"B -> C should have accountable = {:?}",
		expected_forwarded
	);

	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), htlc_bc);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_bc.commitment_signed, false, false);

	// Accountable signal is not surfaced in PaymentClaimable, so we do our next-best and check
	// that the received htlcs that will be processed has the signal set as we expect. We manually
	// process pending update adds so that we can access the htlc in forward_htlcs.
	nodes[2].node.test_process_pending_update_add_htlcs();
	{
		let fwds_lock = nodes[2].node.forward_htlcs.lock().unwrap();
		let recvs = fwds_lock.get(&0).unwrap();
		assert_eq!(recvs.len(), 1);
		match recvs[0] {
			HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
				forward_info: PendingHTLCInfo { incoming_accountable, .. },
				..
			}) => {
				assert_eq!(incoming_accountable, expected_forwarded)
			},
			_ => panic!("Unexpected forward"),
		}
	}

	expect_and_process_pending_htlcs(&nodes[2], false);
	check_added_monitors(&nodes[2], 0);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, 100_000);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}

#[test]
fn test_accountable_signal() {
	// Tests forwarding of accountable signal for various incoming signal values.
	test_accountable_forwarding_with_override(None, false);
	test_accountable_forwarding_with_override(Some(true), true);
	test_accountable_forwarding_with_override(Some(false), false);
}

#[test]
fn test_upgrade_accountability_on_forward() {
	// Tests that when the incoming onion carries `upgrade_accountability` (BOLT 4 TLV type 19)
	// but the incoming `update_add_htlc` does not have `accountable` set, the forwarding node
	// upgrades the outgoing HTLC to accountable. See lightning/bolts#1280.
	//
	// To exercise this end-to-end we build the onion ourselves with `invoice_accountable: true`
	// (which causes `upgrade_accountability` to be included in the forwarding hop's payload),
	// then hand the resulting `update_add_htlc` directly to the forwarding node and observe its
	// outgoing HTLC.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_ab = create_announced_chan_between_nodes(&nodes, 0, 1);
	let _chan_bc = create_announced_chan_between_nodes(&nodes, 1, 2);

	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);

	// Find a route from node 0 to node 2.
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV),
		amt_msat,
	);
	let route = get_route(&nodes[0], &route_params).unwrap();

	// Build the onion with invoice_accountable: true so the forwarding hop sees
	// upgrade_accountability in its payload.
	let secp_ctx = Secp256k1::new();
	let prng_seed = chanmon_cfgs[0].keys_manager.get_secure_random_bytes();
	let session_priv = SecretKey::from_slice(&prng_seed[..]).expect("RNG is busted");
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret, amt_msat);
	let cur_height = nodes[0].best_block_info().1 + 1;
	let (onion_packet, _htlc_msat, _htlc_cltv) = onion_utils::create_payment_onion(
		&secp_ctx,
		&route.paths[0],
		&session_priv,
		&recipient_onion,
		cur_height,
		&payment_hash,
		&None,
		None,
		prng_seed,
		// invoice_accountable
		true,
	)
	.unwrap();

	// Use the standard send_payment flow to set up the payment state at node 0, but replace the
	// outgoing onion with our manually-built one before it leaves node 0.
	let payment_id = PaymentId(payment_hash.0);
	let onion_fields = RecipientOnionFields::secret_only(payment_secret, amt_msat);
	nodes[0]
		.node
		.send_payment(payment_hash, onion_fields, payment_id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let updates_ab = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	assert_eq!(updates_ab.update_add_htlcs.len(), 1);
	// Replace the onion with our accountable-upgraded one. The amounts/cltv match because
	// `create_payment_onion` was given the same route.
	let mut htlc_ab = updates_ab.update_add_htlcs[0].clone();
	htlc_ab.onion_routing_packet = onion_packet;
	assert_eq!(htlc_ab.accountable, Some(false));

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &htlc_ab);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates_ab.commitment_signed, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let updates_bc = get_htlc_update_msgs(&nodes[1], &nodes[2].node.get_our_node_id());
	assert_eq!(updates_bc.update_add_htlcs.len(), 1);
	let htlc_bc = &updates_bc.update_add_htlcs[0];
	assert_eq!(
		htlc_bc.accountable,
		Some(true),
		"B should upgrade the outgoing HTLC to accountable when upgrade_accountability is set",
	);

	// Complete the payment so the test cleans up properly.
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), htlc_bc);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_bc.commitment_signed, false, false);
	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, amt_msat);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}
