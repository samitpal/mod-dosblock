**Mod\_Dosblock** is an apache module written to provide Dos/Ddos protection at the HTTP layer. **Mod\_Dosblock** works on http url or http header and can throttle requests based on the rate of incoming http queries.

This module can be particularly useful in an architecture where the content serving  webservers sit behind reverse proxy apache servers exposed to internet. The gateway servers can throttle/dos protect http queries saving the actual serving web servers.

Mod\_dosblock uses the concept of dos subrules and actual dos rules. Sub rules can be of two types. One is based on the url and the other based on http header. We then define the actual dos rule which works on any of the sub rules defined. We also define the threshold qps (queries per second) etc, blocking time in the same dos rule.

### Installation: ###

Compile using apxs. apxs may not be available by default on systems. You might have to install the required package containing apxs. Generally it comes with the apache devel package. For instance in ubuntu you could install **apache2-prefork-dev** or **apache2-threaded-dev**. You will also need **libapr** and **libapr-dev**.

Download the latest tar file containing the source from the Downloads link. Compile it. The command below should work for the compilation.

sudo apxs2 -i -a -c  <path to mod\_dosblock\_module.c>

The above command will create the shared object file. Copy this under the apache modules directory (i.e /usr/lib/apache2/modules).

You should then create a configuration file called something like /etc/apache2/mods-available/dos\_block.load with the following line in it.

```
LoadModule mod_dosblock_module /usr/lib/apache2/modules/mod_dosblock_module.so ```

Enable the module using something like  _a2enmod_ command.

You might have to reload/restart your apache after this

### Configuration: ###

Currently we support the following directives **DosBlockUrl, DosBlockHeader,  DosBlockRule, DosBlockVerbose**. You can define your configurations in /etc/apache2/mods-enabled/mod\_dosblock.conf.
.

> You can define a **url based subrule**
> using the following syntax

> ```
 DosBlockUrl  <name of the  url subrule> < regexp pattern> ```

> Example

> ```
 DosBlockUrl testurlrule /test ```

> A **header based subrule** can be defined as follows

> ```
 DosBlockHeader <name of the header subrule> <header name>  <regexp pattern> ```

> Example:

> ```
 DosBlockHeader testheaderrule User-Agent mozilla ```

> Then you use the following syntax to do the real blocking

> ```
 DosBlockRule <dos rule name>:<name of the subrule> <threshold rate (hits per  sec)> <time till blockage ( in secs)> ```

> The Dos rule will be blocked for <time till blockage> parameter. But just before attempting to unblock, it will again compute the qps and compare with the threshold rate defined.

> Example:

> ```
 DosBlockRule testdosblock_header:testheaderrule 2 60 ```

> In case you want to enable debugging you can set

> ```
 DosBlockVerbose On ```

> Verbose logging is turned off by default.

> Here is **a complete example**:

> ```
 DosBlockUrl testurlrule /test ```

> ```
 DosBlockRule blocktest:testurlrule 50 120 ```

> ```
 DosBlockVerbose On ```

### Caveats: ###

# Mod\_dosblock calculates rate over 5 minutes while calculating qps for the incoming requests for a given Dos rule. Going forward I might make this a configurable option.

# If there are multiple Dos sub rules and an incoming request matches more than one sub rule, the first sub rule takes precedence.

# After a threshold is reached for a given dos rule, matching requests will get a 403 response. I plan to make it configurable for users to supply an error document.

# Currently combining (logical AND, OR) more that two sub rules is not supported. I plan to support it in a later release.

# I have tested this only on ubuntu on apache 2.2.14 and Fedora 7 with httpd 2.2.4. If you face issues on other platforms please file issues.

### Coming Soon: ###
# Ability for webmasters to view the status of currently blocked dos rules by visiting something like /dosblock-status. There is an issue filed already about this feature.

# Enable custom error page.