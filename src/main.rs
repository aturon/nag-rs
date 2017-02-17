extern crate hyper;
extern crate hyper_openssl;
extern crate hubcaps;
extern crate chrono;
extern crate rand;
extern crate reqwest;
extern crate docopt;

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::fmt;

use hyper::Client;
use hyper::net::HttpsConnector;
use hyper_openssl::OpensslClient;

use hubcaps::{Credentials, Github};
use hubcaps::repositories::Repository;
use hubcaps::rep::{IssueListOptionsBuilder, Issue};

use chrono::{DateTime, UTC};

use docopt::Docopt;

const USAGE: &'static str = "
nag-rs

Usage:
  nag-rs [-d] <token> <file>

Options:
  -d       Dry run; prints emails to stdout
";

error_chain! {
    foreign_links {
        Hubcaps(::hubcaps::Error);
        Reqwest(::reqwest::Error);
        Io(::std::io::Error);
    }
}


#[derive(Debug, Deserialize)]
struct FcpItem {
    issue: FcpIssue,
}

#[derive(Debug, Deserialize)]
struct FcpIssue {
    repository: String,
    number: u64,
    title: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct FcpUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct FcpList(FcpUser, Vec<FcpItem>);

#[derive(Debug)]
enum Kind {
    FCP,
    RFC,
    PR,
}

struct Item {
    number: u64,
    kind: Kind,
    url: String,
    title: String,
    last_update: DateTime<UTC>,
}

impl Item {
    fn from_issue(issue: &Issue, kind: Kind) -> Item {
        Item {
            number: issue.number,
            kind: kind,
            url: issue.html_url.clone(),
            title: issue.title.clone(),
            last_update: issue.updated_at.parse()
                .unwrap_or(UTC::now()),
        }
    }

    fn from_fcp(item: &FcpItem) -> Item {
        Item {
            number: item.issue.number,
            kind: Kind::FCP,
            url: format!("https://github.com/{}/issues/{}",
                         item.issue.repository,
                         item.issue.number),
            title: item.issue.title.clone(),
            last_update: (item.issue.updated_at.clone() + "Z").parse()
                .unwrap_or(UTC::now()),
        }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<p>{:?}: <a href={}>{}</a><br>Last update: {}",
               self.kind, self.url, self.title, self.last_update.date().format("%Y-%m-%d"))
    }
}

#[derive(Clone)]
struct TeamMember {
    login: String,
    email: String,
}

impl TeamMember {
    fn items(&self, rust: &Repository, rfcs: &Repository) -> Result<Vec<Item>> {
        let filter = IssueListOptionsBuilder::new()
            .assignee(&self.login[..])
            .build();
        let mut items: Vec<Item> = rust.issues().list(&filter)?
            .iter()
            .map(|issue| Item::from_issue(issue, Kind::PR))
            .filter(|item| item.url.contains("pull"))
            .collect();

        let filter = IssueListOptionsBuilder::new()
            .assignee(&self.login[..])
            .build();
        items.extend(rfcs.issues().list(&filter)?
                     .iter()
                     .map(|issue| Item::from_issue(issue, Kind::RFC))
                     .filter(|item| item.url.contains("pull")));

        let mut url = String::from("http://rusty-dash.com/api/fcp/");
        url.push_str(&self.login);

        let mut resp = reqwest::get(&url)?;
        let list: FcpList = resp.json()?;
        items.extend(list.1.iter().map(Item::from_fcp));

        items.sort_by_key(|item| item.number);
        items.dedup_by_key(|item| item.number);
        items.sort_by_key(|item| item.last_update);

        Ok(items)
    }

    fn process(&self, dry_run: bool, rust: &Repository, rfcs: &Repository) -> Result<()> {
        let items = self.items(rust, rfcs)?;
        if !items.is_empty() {
            if dry_run {
                write_email(&mut io::stdout(), self, items)
            } else {
                send_email(self, items)
            }
        } else {
            Ok(())
        }
    }
}

fn write_email<W: Write>(f: &mut W, member: &TeamMember, mut items: Vec<Item>)
                         -> Result<()>
{
    writeln!(f, "\
Subject: Rust review list for {date}
From: {from}
To: {to}
MIME-Version: 1.0
Content-Type: text/html

<p>Hello Rust subteam member! You have {total} items awaiting review.
This email contains your reviewing mission for today.
",
                 date=UTC::now().format("%Y-%m-%d"),
                 total=items.len(),
                 from="nagbot@rust-lang.org",
                 to=member.email)?;

    if items.len() > 6 {
        writeln!(f, "<p><b>Three stalest items:</b>")?;
        for item in items.drain(..3) {
            writeln!(f, "{}", item)?
        }

        writeln!(f, "<p><b>Three random items:</b>")?;
        for _ in 0..3 {
            let len = items.len();
            if len == 0 { break; }
            let item = items.swap_remove(rand::random::<usize>() % len);
            writeln!(f, "{}", item)?
        }
    } else {
        writeln!(f, "<p><b>All items:</b>")?;
        for item in items {
            writeln!(f, "{}", item)?
        }
    }

    Ok(())
}

fn send_email(member: &TeamMember, items: Vec<Item>) -> Result<()> {
    let mut child = Command::new("sendmail").arg("-t")
        .stdin(Stdio::piped())
        .spawn()?;

    write_email(&mut io::BufWriter::new(child.stdin.as_mut().unwrap()), member, items)?;

    let status = child.wait()?;
    if !status.success() {
        panic!()
    }

    Ok(())
}

fn run(dry_run: bool, token: &str, input_file: &str) -> Result<()> {
    let ssl = OpensslClient::new().chain_err(|| "couldn't set up SSL")?;
    let connector = HttpsConnector::new(ssl);
    let client = Client::with_connector(connector);
    let github = Github::new(
        "nag-rs",
        client,
        Credentials::Token(token.to_owned())
    );

    let rust = github.repo("rust-lang", "rust");
    let rfcs = github.repo("rust-lang", "rfcs");
    let input = File::open(input_file)
        .chain_err(|| format!("couldn't open input file {}", input_file))?;

    for line in BufReader::new(input).lines() {
        let line = line.chain_err(|| "couldn't read line")?;
        let mut line_iter = line.split(",");
        let member= TeamMember {
            login: line_iter.next().ok_or("malformed input")?.to_owned(),
            email: line_iter.next().ok_or("malformed input")?.to_owned(),
        };

        print_if_err(member.process(dry_run, &rust, &rfcs),
                     &format!("error for {}", member.login));
    }

    Ok(())
}

fn print_if_err(res: Result<()>, msg: &str) {
    if let Err(ref e) = res {
        writeln!(io::stderr(), "{}: {}", e, msg).unwrap();

        for e in e.iter().skip(1) {
            writeln!(io::stderr(), "caused by: {}", e).unwrap();
        }
    }
}

fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let res = run(args.get_bool("-d"),
                  &args.get_str("<token>"),
                  &args.get_str("<file>"));
    print_if_err(res, "error");
}
