#![feature(once_cell)]
#![feature(exit_status_error)]

use color_eyre::{
    eyre::{eyre, Report, Result, WrapErr},
    Help, SectionExt,
};
use inquire::{required, Confirm};
use inquire::{validator::Validation, Password, Select, Text};
use regex::Regex;
use std::io::Write;
use std::process::Command;
use std::{process::Stdio, sync::LazyLock};

enum KeySource {
    GitHub,
    Provided,
}
impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::GitHub => f.write_str("from my GitHub account..."),
            KeySource::Provided => f.write_str("by pasting it here..."),
        }
    }
}

static USERNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    // DNS name restrictions + default linux username restrictions
    Regex::new(r"^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$")
        .wrap_err("couldn't construct username validation regex")
        .suggestion("this isn't your fault (probably?) -- contact the admins")
        .unwrap()
});

enum InfoType<'v> {
    Username(&'v str),
    SSHKey(&'v str),
    Email(&'v str),
    Ok,
}

impl<'v> std::fmt::Display for InfoType<'v> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InfoType::Username(u) => write!(f, "    Username: {u}"),
            InfoType::SSHKey(k) => write!(f, "    SSH Key: {k}"),
            InfoType::Email(e) => write!(f, "    Email: {e}"),
            InfoType::Ok => f.write_str("that looks good!"),
        }
    }
}

#[derive(Default, Debug)]
struct UserInfo {
    username: Option<String>,
    ssh_key: Option<String>,
    email: Option<String>,
}

struct ConcreteInfo<'u> {
    username: &'u str,
    ssh_key: &'u str,
    email: &'u str,
}

impl UserInfo {
    fn get_username(&mut self) -> Result<()> {
        let new = Text::new("okie doke, what's your desired username?").
            with_help_message("this'll be your login, and also your site at `https://[you].{are,is}.profoundly.gay`").
            with_validator(required!("you've gotta have *some* name")).
            with_validator(|input: &str| if USERNAME_RE.is_match(input) {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid("your username must be between 1 and 32 characters, and be a valid DNS label (https://www.ietf.org/rfc/rfc1035.html#section-2.3.1)".into()))
            }).
            with_validator(|input: &str| {
                let status = Command::new("id").
                    arg(input). // not passed to a shell, should be ok
                    stdout(Stdio::null()).
                    stderr(Stdio::null()).
                    status().
                    wrap_err("checking if this username was taken")?;
                if status.success() {
                    Ok(Validation::Invalid(format!("sorry, {input} is taken already").into()))
                } else {
                    // yes, technically this races, but we're not at the scale
                    // where it matters
                    Ok(Validation::Valid)
                }
            }).
            prompt_skippable()?;

        if let Some(val) = new {
            self.username = Some(val)
        }

        Ok(())
    }
    fn get_ssh_key(&mut self) -> Result<()> {
        let Some(key_type) = Select::new(
            "awesome, now how do you want use to get your SSH key?",
            vec![KeySource::GitHub, KeySource::Provided],
        )
        .prompt_skippable()? else {
            return Ok(());
        };

        self.ssh_key = Some(match key_type {
            KeySource::GitHub => {
                let Some(gh_user) = Text::new("    ")
                    .with_placeholder("<your username, without the @>")
                    .with_validator(required!("we've gotta get those login details somehow"))
                    .prompt_skippable()? else {
                        return Ok(());
                    };
                reqwest::blocking::get(format!("https://github.com/{gh_user}.keys"))?.text()?
            },
            KeySource::Provided => match Text::new("    ").
                with_placeholder("ssh-ecdsa ABCadEfe70/afds").
                with_validator(required!("we've gotta get those login details somehow")).
                with_validator(|input: &str| {
                    let mut cmd = Command::new("ssh-keygen").
                        args(["-l", "-f", "-"]).
                        stdin(Stdio::piped()).
                        stdout(Stdio::null()).
                        stderr(Stdio::null()).
                        spawn().
                        wrap_err("checking ssh key")?;
                    let mut stdin = cmd.stdin.take().ok_or_else(|| eyre!("failed to get stdin while checking keydata"))?;
                    std::thread::scope(move |s| {
                        s.spawn(move || {
                            stdin.write_all(input.as_bytes()).
                                wrap_err("passing key in for checking").
                                suggestion("try again then contact the admins -- this (probably) isn't your fault").
                                // unwrap cause this error isn't Sized?
                                unwrap();
                        });
                    });

                    let status = cmd.wait().wrap_err("checking SSH key")?;

                    if status.success() {
                        Ok(Validation::Valid)
                    } else {
                        Ok(Validation::Invalid("that wasn't a valid ssh key".into()))
                    }
                }).
                prompt_skippable()? {
                    Some(v) => v,
                    None => return Ok(()),
            },
        });
        Ok(())
    }

    fn get_email(&mut self) -> Result<()> {
        let new = Text::new("cool, we'll also need your email, in case the admins need to get in touch:").
        with_validator(required!("sorry, but we need to be able to contact you in case of issues")).
        with_validator(|input: &str| match input.split_once('@') {
            Some((local, domain)) if !local.is_empty() && !domain.is_empty() => Ok(Validation::Valid),
            _ => Ok(Validation::Invalid("you've gotta have *at least* an `local@domain` in your email (see https://www.ietf.org/rfc/rfc5322.html#section-3.4)".into()))
        })
        .prompt_skippable()?;

        if let Some(val) = new {
            self.email = Some(val)
        }

        Ok(())
    }

    fn as_concrete(&self) -> Result<ConcreteInfo<'_>> {
        match &self {
            UserInfo {
                ssh_key: Some(ssh_key),
                email: Some(email),
                username: Some(username),
            } => Ok(ConcreteInfo {
                username,
                email,
                ssh_key,
            }),

            _ => Err(eyre!("somehow we missed some information"))
                .with_section(|| format!("{:#?}", self).header("What we got"))
                .suggestion(
                    "contact the admins, it seems like you did something we weren't expecting",
                ),
        }
    }
}

fn run() -> Result<UserInfo> {
    Password::new("First off, what's the passphrase?").
        with_help_message("you got this via direct communication with one of the admins (press Ctrl-R to toggle visibility)").
        with_validator(|input: &str| {
            if std::fs::read_to_string("/etc/signup-tokens").
                wrap_err("checking signup token")?.lines().any(|tok| tok == input) {
                    Ok(Validation::Valid)
            } else {
                // add a 5s sleep, just in case, to make this harder to fuzz
                std::thread::sleep(std::time::Duration::new(5, 0));
                Ok(Validation::Invalid("uhuh. yep. toooootally 🙄".into()))
            }
        }).
        with_display_mode(inquire::PasswordDisplayMode::Masked).
        with_display_toggle_enabled().
        without_confirmation().
        prompt()?;

    let mut info = UserInfo::default();
    info.get_username()?;
    info.get_email()?;
    info.get_ssh_key()?;

    'ok_loop: loop {
        if info.username.is_none() {
            info.get_username()?;
            continue 'ok_loop;
        }
        if info.email.is_none() {
            info.get_email()?;
            continue 'ok_loop;
        }
        if info.ssh_key.is_none() {
            info.get_ssh_key()?;
            continue 'ok_loop;
        }
        let ConcreteInfo {
            username,
            email,
            ssh_key,
        } = info.as_concrete()?;

        let next = Select::new(
            "alright, want to change anything?",
            vec![
                InfoType::Username(&username),
                InfoType::Email(&email),
                InfoType::SSHKey(&ssh_key),
                InfoType::Ok,
            ],
        )
        .with_starting_cursor(3)
        .prompt()?;

        match next {
            InfoType::Username(_) => info.get_username()?,
            InfoType::SSHKey(_) => info.get_ssh_key()?,
            InfoType::Email(_) => info.get_email()?,
            InfoType::Ok => break 'ok_loop,
        }
    }

    if !Confirm::new("I promise on a bucket full of kittens that I will be a chill, drama-free (as much as possible), and reasonable member of this shared server ✋")
        .with_default(true)
        .prompt()? {
        Err(eyre!("sorry, you've gotta promise")).
            suggestion("maybe try saying yes next time?")?;
    }

    Ok(info)
}

fn main() -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    color_eyre::install()?;

    let info = match run() {
        Ok(info) => info,
        // add some nice suggestions to errors
        Err(err) => match err.downcast::<inquire::error::InquireError>() {
            Err(err) => return Err(err),
            Ok(err) => match err {
                inquire::InquireError::NotTTY => {
                    return Err(err).suggestion("try running again from an interactive terminal")
                }
                inquire::InquireError::OperationInterrupted
                | inquire::InquireError::OperationCanceled => {
                    // just bail, no need to display Ctrl-C as an error
                    return Ok(());
                }
                inquire::InquireError::Custom(_) => Err(err)?,
                _ => {
                    return Err(err)
                        .suggestion("contact the admins, this (probably?) isn't your fault")
                }
            },
        },
    };

    let ConcreteInfo {
        username,
        ssh_key,
        email,
    } = info.as_concrete()?;

    println!("alright, setting up that user...");
    Command::new("sudo")
        .arg("adduser")
        .arg(username)
        // don't redirect stdin to allow the user to set their own password
        .status()
        .map_err(|err| err.into())
        .and_then(|status| Ok::<_, Report>(status.exit_ok()?))
        .wrap_err("creating user")
        .suggestion("contact the admins, this (probably?) isn't your fault")?;

    let home_dir = Path::new("/home").join(username);
    let key_path = home_dir.join(".ssh").join("authorized_keys");
    std::fs::write(&key_path, ssh_key)
        .wrap_err("adding authorized ssh key(s)")
        .suggestion("contact the admins, this (probably?) isn't your fault")?;

    Command::new("sudo")
        .args(["setfacl", "-x", "i.am", "-R"])
        .arg(home_dir.join(".ssh"))
        .status()
        .map_err(|err| err.into())
        .and_then(|status| Ok::<_, Report>(status.exit_ok()?))
        .wrap_err("creating user")
        .suggestion("contact the admins, this (probably?) isn't your fault")?;

    let email_path = Path::new("/etc/user-emails/").join(username);
    (|| {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(email_path)?
            .write_all(email.as_bytes())
    })()
    .wrap_err("saving your email")
    .suggestion("contact the admins, this (probably?) isn't your fault")?;

    println!("All done, ssh to {username}@profoundly.gay to get started!");

    Ok(())
}
