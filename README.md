# b2368_fw
Small tool to test, extract and create binary firmware image files for Huawei B2368 device. It might work for other devices using the same firmware image format but it is not tested.

This tool is very alpha, I plan to add more features later on but right now it does the bare minimum.

Documentation will be improved at some point but for now here is a quick reference to what this little tool does.

## Usage

### Check file integrity

    ./b2368_fw -t B2368_V100R001C00SPC085T.bin
Checks firmware trailer validity and file integrity.

### Extract file

    ./b2368_fw -e B2368_V100R001C00SPC085T.bin kernel.bin rootfs.bin
Extract B2368_V100R001C00SPC085T.bin into 'kernel.bin' and 'rootfs.bin' files.

### Create file

    ./b2368_fw -c B2368_V100R001C00SPC085T-mod.bin -k kernel.bin -r rootfs.bin
Creates a valid firmware file from 'kernel.bin' and 'rootfs.bin' files.


## Info

- unk1 to unk8 fields on mstc_trailer struct are items that I could not figure out what they are for yet but based on reverse engineering the firmware upgrade routine on the device, they are not used, so they are set as 0x00 for now.

- The device checks the filename of the firmware file, it must be like B2368_*.bin or it won't even bother checking the file.

**Note: I do not guarantee that this will work for your device, at the very least you should make sure that the original firmware file pass all checks on the -t option to discard your device using a customized variation of this format.**