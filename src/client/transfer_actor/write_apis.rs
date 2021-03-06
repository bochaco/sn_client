use sn_data_types::DebitAgreementProof;
use sn_transfers::ActorEvent;

use crate::client::Client;
use crate::errors::ClientError;

/// Handle Write API msg_contents for a given Client.
impl Client {
    /// Apply a successfull payment locally after TransferRegistration has been sent to the network.
    pub(crate) async fn apply_write_payment_to_local_actor(
        &mut self,
        debit_proof: DebitAgreementProof,
    ) -> Result<(), ClientError> {
        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor
            .register(debit_proof.clone())?
            .ok_or_else(|| ClientError::from("No events to register for proof."))?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event))?;

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use rand::rngs::OsRng;
    use sn_data_types::{Keypair, Sequence};
    use xor_name::XorName;

    #[cfg(feature = "simulated-payouts")]
    pub async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<(), ClientError> {
        let keypair = Keypair::new_ed25519(&mut OsRng);

        let data = Sequence::new_public(keypair.public_key(), XorName::random(), 33323);

        let mut initial_actor = Client::new(Some(keypair)).await?;

        match initial_actor.pay_and_write_sequence_to_network(data).await {
            Err(ClientError::DataError(e)) => {
                assert_eq!(e.to_string(), "Not enough money to complete this operation");
            }
            res => panic!(
                "Unexpected response from mutation msg_contentsuest from 0 balance key: {:?}",
                res
            ),
        }

        Ok(())
    }
}

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use super::ClientError;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<(), ClientError> {
        exported_tests::transfer_actor_with_no_balance_cannot_store_data().await
    }
}
