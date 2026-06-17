use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    // id, name, username, password
    id: Option<u32>,
    name: String,
    filename: String
}

/*
 * REVISE!
 * I need to properly consider how to format this request to the python bridge.
 * A data field composed of a single JSON blob would probably be the best solution to it
 * There is no reason to structure data because it won't be stored anywhere
*/
impl Entry {
    pub fn new(name: String, filename: String) -> Self {
        Self {
            id: None,
            name,
            filename,

        }
    }

    pub fn set_id(&mut self, id: Option<u32>) {
        self.id = id;
    }
}