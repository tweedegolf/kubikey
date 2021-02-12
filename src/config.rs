use std::{env, fs::File, io::Write};

use askama::Template;

#[derive(Template)]
#[template(path = "kubeconfig")]
struct KubeConfig<'a> {
    username: &'a str,
    binary_path: &'a str,
}

pub fn make(username: &str) {
    let bin_path = env::current_exe().expect("Could not deduce path of self");
    let config_template = KubeConfig {
        username,
        binary_path: bin_path
            .to_str()
            .expect("Kubikey binary path should not contain non-ascii characters"),
    };

    let mut kubeconfig_path =
        dirs::home_dir().expect("Could not determine where to put kubectl config");
    kubeconfig_path.push(".kube");
    kubeconfig_path.push("config");

    let mut kubeconfig =
        File::create(kubeconfig_path).expect("Could not open kubectl configuration");
    kubeconfig
        .write_all(config_template.render().unwrap().as_bytes())
        .expect("Could not write kubectl configuration");
}
