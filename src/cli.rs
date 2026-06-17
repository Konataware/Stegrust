// Copyright (C) 2026 João Henrique, João Pedro, João Venturini, Luãn Fernandes
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use clap::Parser;

#[derive(Parser)]
#[command(name = "stegrust")]
#[command(about = "Hides encrypted data within images utilizing steganography.", long_about = None)]
pub struct Cli {
    #[arg(long, conflicts_with_all = &["encode", "decode", "list", "delete", "update"])]
    pub add: bool,

    #[arg(long, conflicts_with_all = &["add", "decode", "list", "delete", "update"])]
    pub encode: bool,

    #[arg(long, conflicts_with_all = &["add", "encode", "list", "delete", "update"])]
    pub decode: bool,

    #[arg(long, conflicts_with_all = &["add", "encode", "decode", "delete", "update"])]
    pub list: bool,

    #[arg(long, conflicts_with_all = &["add", "encode", "decode", "list", "update"])]
    pub delete: bool,

    #[arg(long, conflicts_with_all = &["add", "encode", "decode", "list", "delete"])]
    pub update: bool,

    // mame of the entry (used with --add or --update)
    #[arg(short = 'n', long)]
    pub name: Option<String>,

    // filename of the entry (used with --add or --update)
    #[arg(short = 'f', long)]
    pub filename: Option<String>,

    // ID of the entry (used with --delete or --update)
    #[arg(short = 'd', long)]
    pub id: Option<i64>,

    // input image path (used with --encode or --decode)
    #[arg(short = 'i', long)]
    pub input: Option<String>,

    // output image path (used with --encode)
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    // data to hide (used with --encode)
    #[arg(short = 'm', long)]
    pub data: Option<String>,
}