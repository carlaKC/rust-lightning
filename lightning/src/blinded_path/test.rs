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

	// ***** NB: must change for your environment ******
	// Create a path with the following:
	let introduction_node = PublicKey::from_str("03589ec8a535ecdb21c81b60ad064b393a693da1f63d62b943dead76f91c2eab5b").unwrap();
	let blinded_node = PublicKey::from_str("03d6afc322b64bd8fa025427dcf477150e8bb332bdd1db0cb8492efa0802dbf43f").unwrap();
	let payment_secret = hex::decode("9b929733286c295b8637462fd08b7d368bdd7d89bad95cd4ed6400ac40e6a35a").unwrap();
	let channel_id = 163827232604160;
	// *************************************************

	let mut payment_secret_array = [0u8; 32];
	payment_secret_array.copy_from_slice(&payment_secret);

	let forwarding_tlv = BlindedPaymentTlvs::Forward {
		short_channel_id: channel_id,
		payment_relay: PaymentRelay {
			cltv_expiry_delta: 100,
			fee_proportional_millionths: 10,
			fee_base_msat: 5000,
		},
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: 1000000,
			htlc_minimum_msat: 1 ,
		},
		features: features::BlindedHopFeatures::empty(),
	};

	let receiving_tlv = BlindedPaymentTlvs::Receive {
		payment_secret: PaymentSecret(payment_secret_array),
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: 1000000,
			htlc_minimum_msat: 1,
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

