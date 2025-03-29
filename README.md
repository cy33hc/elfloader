# ELF Loader for BD-J [ez-ps5-jar-loader](https://github.com/cy33hc/ps5-jar-loader)

## Usage

- Download and burn the iso release of [ez-ps5-jar-loader](https://github.com/cy33hc/ps5-jar-loader/releases/latest) onto a BluRay Disc.
- Run the UMTX payload from the disc or send via remote option.
- Send the elfloader.jar payload to your PS5.
- There are multiple options available for sending:

### Netcat
`nc -n <ps5-ip-address> < elfloader.jar`

### Socat
`socat TCP:<ps5-ip-address>:9025 FILE:elfloader.jar`

### GUI options for Windows
- NetCat GUI by Modded Warfare
- Payload Sender by AlAzif (also available for Android)

## Thanks and credits to...
[hammer-83](https://github.com/hammer-83) - For his steady support with his knowledge and tools and of course his jar loader project including his BDJ/PS5 sdk.

[iakdev](https://github.com/iakdev) - For his ideas and motivational support.

[sb/John](https://github.com/ps5-payload-dev) - For his excellent PS5 payload sdk and his elfldr.elf used in this project.

[shahrilnet](https://github.com/shahrilnet) and [Specter](https://github.com/Cryptogenic) - For their LUA and JavaScript versions of an ELF loader used as inspiration.
