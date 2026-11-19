# APD Security


Additional job templates that can run in [Ansible Product Demos](https://github.com/ansible/product-demos) relating to security automation.

## Overview

The playbooks perform the following high-level steps:
1. Install various security related APD demos (currently just PQC)

## Project

-   When using the self installer on Ansible Product Demos, you will have a project called "APD Security"

## Playbooks

- `install_apd_security.yml`: Bootstrapping playbook that installs all resources onto AAP.
- `cbom_creation.yml`: Creates a crytographic bill of materials and uploads it to a designated server

## Requirements

### Execution Environment

These playbooks are intended to be run within an Ansible Execution Environment that is running within Ansible Automation Platform. Execution Environments are container images that serve as the control nodes for Ansible execution, containing Ansible Core, ansible-runner, collections, and any required Python or system dependencies.
An execution environment with all the binaries necessary for these job templates is uploaded and referenced within the repository where need be. That EE is located here:
[https://quay.io/repository/chobbs-sa/spear_ee](https://quay.io/repository/chobbs-sa/spear_ee)

#### Adding an Execution Environment to Ansible Automation Platform (AAP) 2.6/2.7

---

#### Internet-Connected Installation

In a standard internet-connected setup, the Automation Controller can pull the image directly from the external container registry (`quay.io`).

##### Prerequisites
* Administrative access to the Automation Controller UI.
* Automation Controller execution nodes must have outbound internet access to reach `quay.io`.

##### Step-by-Step Instructions

1. **Log in to Automation Controller:**
   Navigate to the Automation Controller web interface and log in with an administrator account.

2. **Add Registry Credentials (Optional but Recommended):**
   *If the repository on Quay.io is public, which for SPEAR it is, you can skip this step. If it is private, follow these steps to add your Quay.io credentials.*
   * In the left navigation menu, under **Administration**, click on **Credentials**.
   * Click the **Add** button.
   * Provide a **Name** (e.g., `Quay.io EE Credential`).
   * Choose **Container Registry** as the Credential Type.
   * Enter the **Authentication URL** (e.g., `https://quay.io`).
   * Enter your **Username** and **Password/Token**.
   * Click **Save**.

3. **Add the Execution Environment:**
   * In the left navigation menu, under **Administration**, click on **Execution Environments**.
   * Click the **Add** button.
   * Fill out the details:
     * **Name:** `Example EE` (or your preferred name)
     * **Image:** `quay.io/example/ee`
     * **Pull:** Select your preferred pull policy. `Always pull` ensures you have the latest tag, while `Only pull if not present before executing` saves bandwidth.
     * **Description:** Add a brief description of what this EE contains.
     * **Registry credential:** If you created a credential in Step 2, select it here.
   * Click **Save**.

4. **Test the Execution Environment:**
   Assign the newly created Execution Environment to a Job Template and run a test job to verify that the Controller can successfully pull the image and execute the playbook.

---

#### Disconnected (Air-Gapped) Environment Installation

In a disconnected environment, the Automation Controller execution nodes cannot reach `quay.io`. You must manually pull the image on a connected machine, transfer it to the air-gapped network, push it to a local registry (like Private Automation Hub), and configure the Controller to use the local registry.

##### Prerequisites
* A bastion/jump machine with internet access and a container runtime installed (`podman` is highly recommended, though `docker` works).
* A secure method for transferring files into the disconnected network (e.g., USB drive, secure file transfer gateway).
* An internal container registry accessible by the Automation Controller (e.g., AAP Private Automation Hub).
* A machine inside the disconnected network with `podman` installed and access to the internal registry.

##### Step-by-Step Instructions

###### Phase 1: Exporting the Image (On the Internet-Connected Machine)

1. Pull the Execution Environment image:
   Open a terminal on your internet-connected machine and use `podman` to pull the image:
   ```bash
   podman pull quay.io/example/ee
   ```

2. Save the image as a tar archive:
   Export the image into a compressed tar file so it can be moved.
   ```bash
   podman save -o example-ee.tar quay.io/example/ee
   ```

3. Transfer the archive:
   Move the `example-ee.tar` file to a machine inside the disconnected network using your organization's approved air-gap file transfer procedure.

###### Phase 2: Importing the Image (On the Disconnected Machine)

1. Load the tar archive:
   On a server inside the disconnected network with `podman` installed, load the transferred image:
   ```bash
   podman load -i example-ee.tar
   ```
   *Verify the image is loaded by running `podman images`.*

2. Tag the image for your internal registry:
   You must tag the loaded image with the hostname of your internal registry (e.g., Private Automation Hub). Replace `private-hub.example.local` with your actual registry hostname.
   ```bash
   podman tag quay.io/chobbs-sa/spear_ee private-hub.example.local/spear_ee
   ```

3. Log in to the internal registry:
   Authenticate with your Private Automation Hub or internal registry:
   ```bash
   podman login private-hub.example.local
   ```

4. Push the image to the internal registry:
   Push the retagged image into your disconnected registry so AAP can access it.
   ```bash
   podman push private-hub.example.local/spear_ee
   ```

###### Phase 3: Configuring Automation Controller

1. Log in to Automation Controller:
   Access the UI of the Automation Controller inside the disconnected network.

2. Add Private Registry Credentials:
   * Go to **Administration** -> **Credentials**.
   * Click **Add**.
   * **Name:** `Private Automation Hub Credential`
   * **Credential Type:** `Container Registry`
   * **Authentication URL:** `https://private-hub.example.local`
   * Add the necessary **Username** and **Password**.
   * Click **Save**.

3. Add the Execution Environment:
   * Go to **Administration** -> **Execution Environments**.
   * Click **Add**.
   * Fill out the details:
     * **Name:** `SPEAR EE (Local)`
     * **Image:** `private-hub.example.local/spear_ee` *(Note: Point to the internal registry, NOT quay.io)*
     * **Pull:** `Only pull if not present before executing` or `Always pull`.
     * **Registry credential:** Select the credential created in the previous step.
   * Click **Save**.

Your disconnected AAP environment is now configured to pull and use the custom Execution Environment from your internal registry!

### Target Systems

-   **Linux**: SSH access and credentials
-   **Windows**: Not available yet
-   **Cisco**: Not available yet

## Configuration

### Usage by Red Hatters

TODO

### Usage by Anyone else

TODO, but its not a lot different

### Disconnected Install

TODO

### Todo

Need to document all of the variables that are needed in an austere environment

## Usage TODO

### Todo

Describe usage