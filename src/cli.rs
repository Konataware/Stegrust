use clap::{ Parser, Subcommand };

#[derive(Parser)]
#[command(name = "stegrust")]
#[command(about = "Hides encrypted data within images utilizing steganography.", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands
}

#[derive(Subcommand)]
pub enum Commands {
    // Encodes data in an image.
    // stegrust --encode --data '{}' --name "nameofentry" --input "/path/to/image" --output "/path/to/output"
    Encode {
        // name field
        //#[arg(short, long)]
        //input: String,

        // Input image
        #[arg(short, long)]
        input: String,

        //filename field
        #[arg(short, long)]
        output: String,

        // data field
        #[arg(short, long)]
        data: String
    },

    Decode {
        // Decodes data from an input image.
        #[arg(short, long)]
        input: String
    },

    List, // TODO
    Add {
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        filename: String
    },
    Update {
        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        name: Option<String>,

        #[arg(short, long)]
        filename: Option<String>
    },

    Delete {
        #[arg(short, long)]
        id: String
    }
}