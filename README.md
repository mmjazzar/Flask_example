# Udacity 4th project - Item Catalog
Goal - Develop a web application that provides a list of items within a variety of categories The web application to be developed in python using the flask framework along with implementing third-party OAuth authentication

To view the website please consider the following:

### VirtualBox

VirtualBox is the software that actually runs the VM. [You can download it from virtualbox.org, here.](https://www.virtualbox.org/wiki/Downloads)  Install the *platform package* for your operating system.  You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it.

**Ubuntu 14.04 Note:** If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center, not the virtualbox.org web site. Due to a [reported bug](http://ubuntuforums.org/showthread.php?t=2227131), installing VirtualBox from the site may uninstall other software you need.

### Vagrant

Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem.  [You can download it from vagrantup.com.](https://www.vagrantup.com/downloads) Install the version for your operating system.

**Windows Note:** The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.


## Run the virtual machine!

Using the terminal, change directory to ItemCatalogProject (**cd ItemCatalogProject**), then type **vagrant up** to launch your virtual machine.

## Running the ItemCatalogProject App
Once it is up and running, type **vagrant ssh**. This will log your terminal into the virtual machine, and you'll get a Linux shell prompt. When you want to log out, type **exit** at the shell prompt.  To turn the virtual machine off (without deleting anything), type **vagrant halt**. If you do this, you'll need to run **vagrant up** again before you can log into it.


Now that you have Vagrant up and running type **vagrant ssh** to log into your VM.  change to the /vagrant directory by typing **cd /vagrant**. This will take you to the shared folder between your virtual machine and host machine.

Type **ls** to ensure that you are inside the directory that contains project.py, database_setup.py, and two directories named 'templates' and 'static'

Now type **python database_setup.py** to initialize the database.

Type **python data.py** to populate the database with category and element items. 

Type **python project.py** to run the Flask web server. In your browser visit **http://localhost:8000** to view the project app.  You should be able to view, add, edit, and delete element items and categories.

## Improvement
- adding git clone.
- enhancing UI.
- Add other OAuth2 providers - Facebook.

## cite
I used the design provided by AbdallahNasser.
https://github.com/AbdallahNasser/Item-catalog
