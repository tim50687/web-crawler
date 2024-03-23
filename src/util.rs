use clap::{Arg, Command};

// This function will return the parsed arguments
pub fn parse_arguments() -> clap::ArgMatches {
    Command::new("web crawler")
        .arg(
            Arg::new("server")
                .short('s')
                .default_value("www.3700.network"),
        )
        .arg(Arg::new("port").short('p').default_value("443"))
        .arg(Arg::new("username").required(true))
        .arg(Arg::new("password").required(true))
        .get_matches()
}
