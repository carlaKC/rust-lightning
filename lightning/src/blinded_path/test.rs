use core::str::FromStr;

use bitcoin::Network;
use bitcoin::secp256k1::{Secp256k1, PublicKey};
use crate::blinded_path::payment::{PaymentConstraints, PaymentRelay};
use crate::ln::{PaymentSecret, features};
use crate::util::test_utils;
use super::BlindedPath;
use super::payment::BlindedPaymentTlvs;

#[test]
fn test_blinded_path() {
	let key_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);
	let secp_ctx = Secp256k1::new();

	// Create a path with the following:
	// Introduction node: 02aa1c970ebf082e05e9b9a94728415ba629d8a33560ee64008f7ccae1ecbde03b.
	// Blinded node: 0364751492b41295a8e3530ebb3c565ac96d06cbd2603f704b573f2a834d72fa86.
	// They are connected by: 183618441969665.
	let introduction_node = PublicKey::from_str("02aa1c970ebf082e05e9b9a94728415ba629d8a33560ee64008f7ccae1ecbde03b").unwrap();
	let blinded_node = PublicKey::from_str("0364751492b41295a8e3530ebb3c565ac96d06cbd2603f704b573f2a834d72fa86").unwrap();

	let forwarding_tlv = BlindedPaymentTlvs::Forward {
		short_channel_id: 183618441969665,
		payment_relay: PaymentRelay {
			cltv_expiry_delta: 120,
			fee_proportional_millionths: 10,
			fee_base_msat: 5000,
		},
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: 1000000,
			htlc_minimum_msat: 1000000 ,
		},
		features: features::BlindedHopFeatures::empty(),
	};

	let receiving_tlv = BlindedPaymentTlvs::Receive {
		payment_secret: PaymentSecret([0;32]),
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: 1000000,
			htlc_minimum_msat: 1000000,
		},
		features: features::BlindedHopFeatures::empty(),
	};

	let path = [
		(introduction_node,forwarding_tlv),
		(blinded_node, receiving_tlv),
	];

	let blinded_payment = BlindedPath::new_for_payment(&path[..], &key_manager, &secp_ctx).unwrap();

	println!("Details: cltv {}, fee base {}, prop {}, min {}",
		   blinded_payment.0.cltv_expiry_delta,
		   blinded_payment.0.fee_base_msat,
		   blinded_payment.0.fee_proportional_millionths,
		   blinded_payment.0.htlc_minimum_msat,
		);

	println!("Introduction: {}", blinded_payment.1.introduction_node_id);
	println!("Blinding Point: {}", blinded_payment.1.blinding_point);
	println!("Blinded hops {}", blinded_payment.1.blinded_hops.len());

	for blinded_hop in blinded_payment.1.blinded_hops.iter() {
		println!("Blinded node ID: {}", blinded_hop.blinded_node_id);
		println!("Encrypted Data: {:?}", hex::encode(&blinded_hop.encrypted_payload));
	}
}

