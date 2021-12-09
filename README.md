1. Download osTicket version 1.15.4 and extract it in a directory of your choice inside your system. This documentation is going to use `$OSTFILES` to refer to the path to this directory. Be sure to include the greek language plugin in your osTicket download.
2. Download the saml plugin for osTicket and extract it in a directory of your choice inside your system. This documentation is going to use `$SSPFILES` to refer to the path to this directory.
3. Inside `$SSPFILES` replace `hooks.php` and `saml.php` with the same named files inside `saml-ssp-updates` on this project.
4. Install the `apache2`, `php`, `libapache2-mod-php`, `mariadb-server`, `php-mysql`, `php-dom` and `simplesamlphp` packages.
5. On `/etc/apache2/sites-enabled/` replace the contents of `000-default.conf` file with the contents of `/etc/apache2/sites-available/default-ssl.conf` and replace the certificate filepaths inside with paths to the certificates for your osTicket.
6. Enable simplesamlphp (`a2enconf simplesamlphp`, `systemctl reload apache2`) and ssl (`a2emod ssl`, `systemctl restard apache2`) on apache server and check if you can access the server from your browser through https using the correct domain name (e.x. `https://helpdesk-devel.uoa.gr`). If everything up to this point was done correctly, you should see the Apache2 Default Page on your browser.
7. Create a new mysql database (`CREATE DATABASE osticket;`) and a new user that  osTicket will use to access the database (`CREATE USER 'osticket'@'localhost' IDENTIFIED BY 'yourPassword';` `GRANT ALL PRIVILEGES ON osticket.* TO 'osticket'@'localhost';`)
8. Create a home directory for osTicket inside your apache. (ex. `/var/www/html/osticket`). This documentation is going to use `$OSTHOME` to refer to the path to this directory.
9. Copy the contents of the `$OSTFILES/upload` directory to `$OSTHOME`. If no `upload` directory exists inside the `$OSTFILES` directory, there are probably more things you need to extract in `$OSTFILES`.
10. Copy the file `$OSTFILES/el.phar` inside the directory `$OSTHOME/include/i18n` to install the greek language patch.
11. Copy all the files inside `$SSPFILES` to the directory `$OSTHOME/include/plugins` to install the saml plugin.
12. Rename the file `ost-sampleconfig.php` in `$OSTHOME/include` to `ost-config.php` and grant read and write priviledges (`chmod 0666 ost-config.php`).
13. Access osTicket from a web browser (ex. `http://helpdesk-devel.uoa.gr/osticket`), fill the information required by the forms and press the button at the bottom of the screen to complete the installation. Sometimes a white screen might show up in this step, even though the installation was properly completed. If it does, just ignore it.
14. Run the file `db-updates.sql` on the database you created previously for osTicket.
15. Delete the directory `$OSTHOME/setup` for security reasons.
16. Change back the privileges on `$OSTHOME/include/ost-config.php` for security reasons (ex. `chmod 644 $OSTHOME/include/ost-config.php`)
17. Login to osTicket from your browser as Admin (ex. `http://helpdesk-devel.uoa.gr/osticket/scp/login.php`). In the admin screen, go to `Manage` &#8594; `Plugins`. You should see a page with "Currently Installed Plugins" at the top and a table with the only row there saying "No plugins installed yet - add one !". Click on the "add one" and click the "Install" button next to "SAML Authentication for Clients and Staff based on simpleSAMLphp".
18. Back on the "Currently Installed Plugins" screen, click on the "SAML Authentication for Clients and Staff based on simpleSAMLphp". On the next screen, pick "Agents/Admins and Clients" for "SAML Mode Support". On "SimpleSAMLphp path" put "/usr/share/simplesamlphp", "uoa-ost-sp" on "Client Authentication Source" and "Staff Authentication Source" and "https://wayf.grnet.gr/" on "Discovery Service URL". Check the boxes next to "Single Log Out", "Username manipulation", "Create client if not exists", "Update client data", "Create agent/staff if not exists" and "Update staff data" and pick "Agent" for "Default System Role". Finally, put "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" on the field next to "Username", "urn:oid:0.9.2342.19200300.100.1.3" on "E-mail", "urn:oid:2.5.4.42" on "Firstname", "urn:oid:2.5.4.4" for "Lastname", "role" for "Primary Role" and "department" for "Primary Departament". After you're done click "Save Changes" at the botom of the page, go back to the "Currently Installed Plugins" screen and enable the plugin by ticking the box on the left, then clicking "More" on the upper right and picking "Enable" from the dropdown.
19. Copy the files `/usr/share/simplesamlphp/modules/cron/config-templates/module_cron.php` and `/usr/share/simplesamlphp/modules/metarefresh/config-templates/config-metarefresh.php` to `/etc/simplesamlphp/` and then create the empty files `/usr/share/simplesamlphp/modules/cron/enable` and `/usr/share/simplesamlphp/modules/metarefresh/enable` to enable the simplesamlphp cron plugin and the simplesamlphp metarefresh plugin. We will need these plugins to fetch our metadata.
20. Create the directory `/etc/simplesamlphp/metadata/metadata-identity/` if it doesn't exist, change the owner to the apache user (`www-data`) and in `/etc/simplesamlphp/config.php` go to line 69 and replace the path in `metadatadir` with the path of the directory you just created. Also, in the same file, add the line `['type' => 'flatfile','directory' => 'metadata/metadata-identity'],` bellow line 1143.
21. Create a new database for simplesamlphp to use (`CREATE DATABASE simplesamlphp DEFAULT CHARACTER SET utf8;`) and a user for simplesamlphp to access the database with (`CREATE USER 'simplesamlphp'@'localhost' IDENTIFIED BY 'yourPassword';` `GRANT ALL PRIVILEGES ON simplesamlphp.* TO 'simplesamlphp'@'localhost';`) and change the parameters `store.sql.dns`, `store.sql.username` and `store.sql.password` in the file `/etc/simplesamlphp/config.php` with the database link, username and password, as well as the parameter `store.type` from `phpsession` to `sql`.  (e.x. `'store.sql.dsn' => 'mysql:host=localhost;dbname=simplesamlphp'`, `'store.sql.username' => 'simplesamlphp'`, `'store.sql.password' => 'yourPassword'`)
22. Put the certificate `uoa-ost.crt` and its key `uoa-ost.key` inside `/etc/ssl/certs`, then open the file `/etc/simplesamlphp/authsources.php` and at the botom of the file and before the line with `);` add the following code:
```
'uoa-ost-sp' => array(
        'saml:SP',
        'entityID' => NULL,
        'privatekey' => 'uoa-ost.key',
        'certificate' => 'uoa-ost.crt',
        'attributes' => array('urn:oid:1.3.6.1.4.1.5923.1.1.1.6'),
        'name' => array('en' => 'UoA OSTicket','el' => 'UoA OSTicket'),
        'authproc' => array(
                20 => 'saml:NameIDAttribute',
        ),
    ),
```

23. On the file `/etc/simplesamlphp/config-metarefresh.php` replace the config array inside with the following code:
```
$config = array(
        'sets' => array(

                'grnet' => array(
                        'cron'          => array('hourly'),
                        'sources'       => array(
                                array(
                                        'src' => 'https://md.aai.grnet.gr/aggregates/grnet-metadata.xml',
                                        'types' => array('saml20-idp-remote'),
                                ),
                        ),
                        'expireAfter'           => 60*60*24*4,
                        'outputDir'     => 'config/metadata/metadata-identity/',
                        'outputFormat' => 'flatfile',
                ),
        ),
);
```
24. Access simplesamlphp from your browser (e.x. `https://helpdesk-devel.uoa.gr/simplesamlphp`), go to the "Federation" tab and bellow "Tools", click on "Metarefresh: fetch metadata". You will be asked to give the admin password. You can find this password inside the file `/var/lib/simplesamlphp/secrets.inc.php`. After giving the password, you should see a screen with the following message:
```
16:20:11.418Z [metarefresh]: Executing set [grnet]
16:20:11.421Z [metarefresh]: In set [grnet] loading source [https://md.aai.grnet.gr/aggregates/grnet-metadata.xml]
16:20:12.166Z Writing: /usr/share/simplesamlphp/config/metadata/metadata-identity/saml20-idp-remote.php
```
If you see anything else, something is wrong with the installation.

25. Open the file `/etc/crontab` and at the botom of the file add the following line of code: `01 * * * * root curl --silent "https://helpdesk-devel.uoa.gr/simplesamlphp/module.php/cron/cron.php?key=veryverysecret...&tag=hourly" > /dev/null 2>&1 < /dev/null`

26. You should now be able to login using SAML as a User from `https://helpdesk-devel.uoa.gr/osticket` and as Staff from `https://helpdesk-devel.uoa.gr/osticket/scp`
