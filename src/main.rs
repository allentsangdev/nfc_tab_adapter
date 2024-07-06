use pcsc::*;

fn load_authentication_key(reader_connection: &Card, key_location: u8, key: &[u8]) -> Result<(), Error> {
    println!("Key length {}", key.len());
    if key.len() != 6 {
        return Err(Error::InvalidValue);
    }

    let mut command = vec![0xFF, 0x82, 0x00, key_location, 0x06];
    command.extend_from_slice(key);

    let mut response = [0; 258];
    let  rapdu = reader_connection.transmit(&command, &mut response);

    if rapdu.is_err() {
        println!(
            "Failed to load auth key to reader: {:?}",
            rapdu.unwrap_err()
        );
    } else {
        println!("APDU response: {:?}", rapdu.unwrap());
        println!("Data: {:?}", response);
    }

    Ok(())
}

fn authenticate_block(reader_connection: &Card, block: u8, key_type: u8, key_number: u8) -> Result<(), Error> {
    // APDU command structure:
    // FF 86 00 00 05 01 00 <block> <key_type> <key_number>
    let command = [
        0xFF, 0x86, 0x00, 0x00, 0x05, 
        0x01, 0x00, block, key_type, key_number
    ];

    let mut response = [0; 258];
    let rapdu = reader_connection.transmit(&command, &mut response);

    if rapdu.is_err() {
        println!(
            "Failed to authenticate block: {:?}",
            rapdu.unwrap_err()
        );
    } else {
        println!("Authenticated block APDU response: {:?}", rapdu.unwrap());
        println!("Data: {:?}", response);
    }

    Ok(())

}


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

            let reader_connection = ctx.connect(name, ShareMode::Shared, Protocols::ANY).expect("No Cards Detected");

            // load auth key to reader
            let key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
            let key_location = 0x00;
            match load_authentication_key(&reader_connection, key_location, &key) {
                Ok(()) => println!("Authentication key loaded successfully into reader"),
                Err(e) => println!("Error loading authentication key into reader: {:?}", e),
            }

            // use the loaded auth key in 0x00 to authehticate 
            let key_type = 0x60;
            let block = 0x04;
            match authenticate_block(&reader_connection, block,  key_type, key_location) {
                Ok(()) => println!("Authenticated block 04"),
                Err(e) => println!("Error authenticating block 04: {:?}", e),
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

                    println!("Sending uuid: {:?}", uuid_bytes);

                    // update binary
                    // let apdu = b"\xFF\xD6\x00\x01\x10\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
                    // which block are we updatin here? --> 04
                    // Class/INS/P1/Block Number/Number of Bytes to Update/ Data
                    // let apdu = &[b"\xFF\xD6\x00\x04\x10", &uuid_bytes[..]].concat()[..];
                    // read binary
                    let apdu = b"\xFF\xB0\x00\x04\x10";
                    println!("Sending APDU: {:?}", apdu);
                    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
                    // println!("buf {:?}", rapdu_buf);

                    let rapdu = card.transmit(apdu, &mut rapdu_buf);

                    if rapdu.is_err() {
                        println!(
                            "Failed to transmit APDU command to card: {:?}",
                            rapdu.unwrap_err()
                        );
                    } else {
                        println!("APDU response: {:?}", rapdu.unwrap());
                        println!("Data: {:?}", rapdu_buf);

                        let valid_data = &rapdu_buf[..10];

                        match std::str::from_utf8(valid_data) {
                            Ok(decoded_string) => {
                                println!("Decoded Response: {}", decoded_string);
                            }
                            Err(e) => {
                                eprintln!("Failed to decode buffer: {}", e);

                            }
                        }


                    }
                }
            }
        }
    }
}