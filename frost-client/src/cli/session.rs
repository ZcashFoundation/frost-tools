use std::error::Error;

use eyre::{eyre, OptionExt as _};
use rand::thread_rng;

use crate::{api, client::Client};

use super::{args::Command, config::Config};

pub async fn list(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Sessions {
        config,
        group,
        server_url,
        close_all,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let server_url = if let Some(server_url) = server_url {
        server_url
    } else if let Some(group) = group {
        let group = config.group.get(&group).ok_or_eyre("Group not found")?;
        group
            .server_url
            .clone()
            .ok_or_eyre("the group specified does not have an associated server URL")?
    } else {
        return Err(eyre!("must specify either server_url or group").into());
    };

    let comm_privkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .privkey
        .clone();
    let comm_pubkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .pubkey
        .clone();

    let mut client = Client::new(format!("https://{server_url}"));

    let mut rng = thread_rng();

    let challenge = client.challenge().await?.challenge;

    let signature: [u8; 64] = comm_privkey.sign(challenge.as_bytes(), &mut rng)?;

    client
        .login(&api::LoginArgs {
            challenge,
            pubkey: comm_pubkey.clone(),
            signature: signature.to_vec(),
        })
        .await?;

    // Get session ID from server
    let r = client.list_sessions().await?;

    if r.session_ids.is_empty() {
        eprintln!("No active sessions.");
    } else {
        for session_id in r.session_ids {
            let r = client
                .get_session_info(&api::GetSessionInfoArgs { session_id })
                .await?;
            let coordinator = config.contact_by_pubkey(&r.coordinator_pubkey);
            let participants: Vec<_> = r
                .pubkeys
                .iter()
                .map(|pubkey| config.contact_by_pubkey(pubkey))
                .collect();
            eprintln!("Session with ID {session_id}");
            eprintln!(
                "Coordinator: {}",
                coordinator
                    .map(|c| c.name)
                    .unwrap_or("(Unknown contact)".to_string())
            );
            eprintln!("Signers: {}", participants.len());
            for participant in participants {
                if let Ok(participant) = participant {
                    eprintln!(
                        "\t{}\t({})",
                        participant.name,
                        hex::encode(&participant.pubkey.0)
                    );
                } else {
                    eprintln!("\t(Unknown contact)");
                }
            }
            eprintln!();

            if close_all {
                client
                    .close_session(&api::CloseSessionArgs { session_id })
                    .await?;
            }
        }
    }

    Ok(())
}
