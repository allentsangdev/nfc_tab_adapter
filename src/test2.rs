use pcsc::*;

fn main() {
    let ctx = Context::establish(Scope::User).expect("failed to establish context");

    let mut readers_buf = [0; 2048];
    let mut reader_states = vec![
        // Listen for reader insertions/removals, if supported.
        ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
    ];
    loop {
        // Remove dead readers.
        fn is_dead(rs: &ReaderState) -> bool {
            rs.event_state().intersects(State::UNKNOWN | State::IGNORE)
        }
        for rs in &reader_states {
            if is_dead(rs) {
                println!("Removing {:?}", rs.name());
            }
        }
        reader_states.retain(|rs| !is_dead(rs));

        // Add new readers.
        let names = ctx
            .list_readers(&mut readers_buf)
            .expect("failed to list readers");
        for name in names {
            if !reader_states.iter().any(|rs| rs.name() == name) {
                println!("Adding {:?}", name);
                reader_states.push(ReaderState::new(name, State::UNAWARE));
            }
        }

        // Update the view of the state to wait on.
        for rs in &mut reader_states {
            rs.sync_current_state();
        }

        // Wait until the state changes.
        ctx.get_status_change(None, &mut reader_states)
            .expect("failed to get status change");

        // Print current state.
        println!();
        for rs in &reader_states {
            if rs.name() != PNP_NOTIFICATION() {
                println!("{:?} {:?} {:?}", rs.name(), rs.event_state(), rs.atr());
                if rs.event_state().contains(State::PRESENT) {
                    println!("Card present");

                    // read card
                    let card = ctx
                        .connect(rs.name(), ShareMode::Shared, Protocols::ANY)
                        .expect("failed to connect to card");

                    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];

                    let apdu = b"\xFF\x86\x00\x00\x05\x01\x00\x04\x60\x00";

                    let rapdu = card.transmit(apdu, &mut rapdu_buf);

                    if rapdu.is_err() {
                        println!(
                            "Failed to transmit APDU command to card: {:?}",
                            rapdu.unwrap_err()
                        );
                    } else {
                        println!("APDU response: {:?}", rapdu.unwrap());
                        println!("Data: {:?}", rapdu_buf);
                    }

                    let uuid_str = "d9a890d0-bbf1-4c20-bf85-6a6f0ea2a5ad";

                    // Remove hyphens
                    let uuid_str_no_hyphens = uuid_str.replace("-", "");

                    // Convert to byte array
                    let uuid_bytes = (0..uuid_str_no_hyphens.len())
                        .step_by(2)
                        .map(|i| {
                            u8::from_str_radix(&uuid_str_no_hyphens[i..i + 2], 16)
                                .expect("Parsing error")
                        })
                        .collect::<Vec<u8>>();
                    // update binary
                    let apdu = &[b"\xFF\xD6\x00\x04\x10", &uuid_bytes[..]].concat()[..];
                    // read binary
                    println!("Sending APDU: {:?}", apdu);

                    let rapdu = card.transmit(apdu, &mut rapdu_buf);

                    if rapdu.is_err() {
                        println!(
                            "Failed to transmit APDU command to card: {:?}",
                            rapdu.unwrap_err()
                        );
                    } else {
                        println!("APDU response: {:?}", rapdu.unwrap());
                        println!("Data: {:?}", rapdu_buf);
                    }

                    let apdu = b"\xFF\xB0\x00\x04\x10";
                    let rapdu = card.transmit(apdu, &mut rapdu_buf);

                    if rapdu.is_err() {
                        println!(
                            "Failed to transmit APDU command to card: {:?}",
                            rapdu.unwrap_err()
                        );
                    } else {
                        println!("APDU response: {:?}", rapdu.unwrap());
                        println!("Data: {:?}", rapdu_buf);
                        // Convert to string
                        let uuid_str = rapdu_buf
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<String>>()
                            .join("");
                        println!("UUID: {:?}", uuid_str);
                    }
                }
            }
        }
    }
}