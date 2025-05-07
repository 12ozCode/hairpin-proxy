#!/usr/bin/env python3

import os
import time
import socket
import logging
import argparse
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# --- Constants ---
COMMENT_LINE_SUFFIX = "# Added by hairpin-proxy"
DNS_REWRITE_DESTINATION = "hairpin-proxy.hairpin-proxy.svc.cluster.local"
POLL_INTERVAL = max(5, int(os.getenv("POLL_INTERVAL", "60")))

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger(__name__)

class HairpinProxyController:
    def __init__(self):
        # Load Kubernetes in-cluster configuration (assumes running as Pod in the cluster)
        config.load_incluster_config()
        self.core_api = client.CoreV1Api()
        self.ingress_api = self.detect_ingress_api()

    def detect_ingress_api(self):
        """
        Detect which Ingress API version is available:
        networking.k8s.io/v1 or extensions/v1beta1 (older clusters).
        Returns the usable API client.
        """
        try:
            api = client.NetworkingV1Api()
            api.list_ingress_for_all_namespaces(limit=1)
            log.info("Using Ingress API: networking.k8s.io/v1")
            return api
        except ApiException as e:
            log.info(f"Ingress API networking.k8s.io/v1 not available: {str(e)}")

        try:
            api = client.ExtensionsV1beta1Api()
            api.list_ingress_for_all_namespaces(limit=1)
            log.info("Using Ingress API: extensions/v1beta1")
            return api
        except ApiException as e:
            log.info(f"Ingress API extensions/v1beta1 not available: {str(e)}")

        raise Exception("No supported Ingress API versions found!")

    def fetch_ingress_hosts(self):
        """
        Collect all unique hostnames from the Ingress resources
        — from both tls.hosts and rules.host fields.
        """
        ingresses = self.ingress_api.list_ingress_for_all_namespaces().items
        tls_hosts = []
        rule_hosts = []

        for ingress in ingresses:
            # Extract hosts from spec.tls.hosts
            if ingress.spec.tls:
                for tls in ingress.spec.tls:
                    tls_hosts.extend(tls.hosts or [])
            # Extract hosts from spec.rules.host
            if ingress.spec.rules:
                for rule in ingress.spec.rules:
                    if rule.host:
                        rule_hosts.append(rule.host)

        # Filter valid hostnames only (letters, numbers, dots, hyphens, underscores)
        all_hosts = set(tls_hosts + rule_hosts)
        valid_hosts = sorted(
            h for h in all_hosts if h and all(c.isalnum() or c in ".-_" for c in h)
        )
        return valid_hosts

    def coredns_corefile_with_rewrite_rules(self, original_corefile, hosts):
        """
        Create a new CoreDNS Corefile with rewrite rules for the given hosts.
        Previous rewrite lines added by this script are replaced.
        """
        # Remove any previously inserted rewrite lines
        lines = [line for line in original_corefile.strip().splitlines()
                 if not line.strip().endswith(COMMENT_LINE_SUFFIX)]

        # Generate new rewrite lines
        rewrite_lines = [
            f"    rewrite name {host} {DNS_REWRITE_DESTINATION} {COMMENT_LINE_SUFFIX}"
            for host in hosts
        ]

        # Find the ".:53 {" block to insert the rewrite lines into
        try:
            main_server_index = next(
                i for i, line in enumerate(lines) if line.strip().startswith(".:53 {")
            )
        except StopIteration:
            raise Exception("Can't find '.:53 {' in Corefile")

        # Insert rewrite rules just below the ".:53 {" line
        for i, rewrite in enumerate(rewrite_lines):
            lines.insert(main_server_index + 1 + i, rewrite)

        return "\n".join(lines)

    def check_and_rewrite_coredns(self):
        """
        Update CoreDNS ConfigMap if the set of rewrite rules needs to change.
        """
        log.info("Polling all Ingress resources and CoreDNS configuration...")
        hosts = self.fetch_ingress_hosts()
        cm = self.core_api.read_namespaced_config_map("coredns", "kube-system")

        old_corefile = cm.data["Corefile"]
        new_corefile = self.coredns_corefile_with_rewrite_rules(old_corefile, hosts)

        # Only update if changes detected
        if old_corefile.strip() != new_corefile.strip():
            log.info("Corefile has changed. Updating ConfigMap...")
            cm.data["Corefile"] = new_corefile
            self.core_api.replace_namespaced_config_map("coredns", "kube-system", cm)
        else:
            log.info("No changes needed in CoreDNS Corefile.")

    def dns_rewrite_destination_ip_address(self):
        """
        Resolve the destination service DNS name to an IP address.
        """
        return socket.gethostbyname(DNS_REWRITE_DESTINATION)

    def etchosts_with_rewrite_rules(self, original_hosts, hosts):
        """
        Modify the given /etc/hosts content to map the given hosts to the
        hairpin proxy IP address. Preserve unmanaged lines.
        """
        lines = original_hosts.strip().splitlines()

        # Separate lines we previously added and all others
        our_lines = [line for line in lines if line.strip().endswith(COMMENT_LINE_SUFFIX)]
        other_lines = [line for line in lines if not line.strip().endswith(COMMENT_LINE_SUFFIX)]

        ip = self.dns_rewrite_destination_ip_address()
        hostlist = " ".join(hosts)
        new_rewrite_line = f"{ip}\t{hostlist} {COMMENT_LINE_SUFFIX}"

        # If the managed line is already correct, return unchanged
        if our_lines == [new_rewrite_line]:
            return original_hosts

        # Otherwise, replace the managed line
        return "\n".join(other_lines + [new_rewrite_line]) + "\n"

    def check_and_rewrite_etchosts(self, etchosts_path):
        """
        Update the /etc/hosts file at the given path if necessary.
        """
        log.info(f"Polling all Ingress resources and etchosts at {etchosts_path}...")
        hosts = self.fetch_ingress_hosts()

        with open(etchosts_path, "r") as f:
            old_hosts = f.read()

        new_hosts = self.etchosts_with_rewrite_rules(old_hosts, hosts)

        # Write only if changes detected
        if old_hosts.strip() != new_hosts.strip():
            log.info("/etc/hosts has changed. Writing new file...")
            with open(etchosts_path, "w") as f:
                f.write(new_hosts)
        else:
            log.info("No changes needed in /etc/hosts.")

    def main_loop(self, etchosts_path):
        """
        Main polling loop: checks either CoreDNS or /etc/hosts periodically.
        """
        log.info(f"Starting main loop with polling interval {POLL_INTERVAL}s.")
        if etchosts_path:
            log.info(f"Running in /etc/hosts mode on {etchosts_path}.")
        else:
            log.info("Running in CoreDNS mode.")

        while True:
            try:
                if etchosts_path:
                    self.check_and_rewrite_etchosts(etchosts_path)
                else:
                    self.check_and_rewrite_coredns()
            except Exception as e:
                log.error(f"Error: {e}")
            time.sleep(POLL_INTERVAL)

# --- Main execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--etc-hosts", help="Path to writable /etc/hosts file")
    args = parser.parse_args()

    # Validate that the /etc/hosts file exists and is writable if specified
    if args.etc_hosts and not (os.path.exists(args.etc_hosts) and os.access(args.etc_hosts, os.W_OK)):
        raise FileNotFoundError(f"{args.etc_hosts} does not exist or is not writable")

    controller = HairpinProxyController()
    controller.main_loop(args.etc_hosts)
