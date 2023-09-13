/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>		/* kmalloc() */
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Aries Gunawan"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    /**
     * TODO: handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; /* save for other methods */

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    struct aesd_circular_buffer *dev_buffer = dev->data;
    size_t entry_offset_byte_rtn;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev_buffer, *f_pos, &entry_offset_byte_rtn);
    PDEBUG("offset %lld\n", entry_offset_byte_rtn);

    if (entry == NULL) {
        goto out;
    }
    PDEBUG("read %lld size\n", entry->size);
    
    if (count > entry->size) {
        count = entry->size;
    }
    if (count + entry_offset_byte_rtn > entry->size) {
        count = entry->size - entry_offset_byte_rtn;
    }

    if (copy_to_user(buf, entry->buffptr + entry_offset_byte_rtn, count)) {
        retval = -EFAULT;
        goto out;
    }

    *f_pos += count;
    retval += count;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
	
    ssize_t retval = -ENOMEM;;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    /**
     * TODO: handle write
     */
    struct aesd_buffer_entry* entry;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    if (dev->temp_write == NULL) {
        entry = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
        if (!entry) {
            retval = -ENOMEM;
            goto out;
        }
        entry->size = 0;
        entry->buffptr = kmalloc(sizeof(char) * MAX_ENTRY_BYTES, GFP_KERNEL);
        memset(entry->buffptr, 0, MAX_ENTRY_BYTES * sizeof(char));
        
        dev->temp_write = entry;
    } else {
        entry = dev->temp_write;
    }

    PDEBUG("size %zu bytes with offset %lld %lld", count, entry->size, sizeof(char));

    if (copy_from_user(entry->buffptr + entry->size, buf, count)) {
        retval = -EFAULT;
        goto out;
    }
    entry->size += count;

    if (buf[count-1] == '\n') {
        // Save to circular buffer
        PDEBUG("Saving to circular buffer\n");
        aesd_circular_buffer_add_entry(dev->data, entry);

        dev->temp_write = NULL;
    }

    *f_pos += count;
    retval = count;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence) {
	struct aesd_dev *dev = filp->private_data;
    struct aesd_circular_buffer* dev_buffer = dev->data;
	loff_t newpos;

    struct aesd_buffer_entry *entry;

    PDEBUG("Calling llseek offset %ld, whence %d\n", off, whence);

	switch(whence) {
	  case SEEK_SET: /* SEEK_SET */
        size_t entry_offset_byte_rtn;

        entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev_buffer, off, &entry_offset_byte_rtn);
        if (entry == NULL) {
            return -EINVAL;
        }

		newpos = entry->buffptr + entry_offset_byte_rtn;
		break;

	  case SEEK_CUR: /* Increment or decrement file position*/
		newpos = filp->f_pos + off;
		break;

	  case SEEK_END: /* Use EOF as file position */
        size_t total_size = 0;
        uint8_t index;

        AESD_CIRCULAR_BUFFER_FOREACH(entry, dev_buffer, index) {
            total_size += entry->size;
        }

		newpos = total_size + off;
		break;

	  default: /* can't happen */
		return -EINVAL;
	}
    PDEBUG("llseek new pos %ld, whence %d\n", newpos, whence);

	if (newpos < 0) return -EINVAL;
	filp->f_pos = newpos;
    
	return newpos;
}

/**
 * Adjust the file offset (f_pos) parameter of @param filp based on the location specified by
 * @param write_cmd (the zero referenced command to locate)
 * and @param write_cmd_offset (the zero referenced offset into the command)
 * @return 0 if successful, negative if error occured:
 * 		-ERESTARTSYS if mutex could not be obtained
 * 		-EINVAL if write command or write_cmd_offset was out of range
*/
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset) {

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    struct aesd_circular_buffer *dev_buffer = dev->data;
    size_t entry_offset_byte_rtn;
    size_t start_offset = 0;

    long retval = 0;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos_seek(dev_buffer, write_cmd, &start_offset);

    PDEBUG("filp  %ld %ld \n", start_offset, entry);

    if (entry == NULL) {
        return -EINVAL;
    }

    if (write_cmd_offset >= entry->size) {
        return -EINVAL;
    }

    filp->f_pos = start_offset + write_cmd_offset;

    PDEBUG("filp f_post %ld %ld %ld\n", start_offset, write_cmd_offset, filp->f_pos);

out:
    mutex_unlock(&dev->lock);
    return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    // inode argument -> filp->f_inode

    long retval = -EINVAL;

    PDEBUG("ioctl %d\n", cmd);

    switch (cmd) {
        case AESDCHAR_IOCSEEKTO:
            struct aesd_seekto seekto;

            if (copy_from_user(&seekto, (const void __user *) arg, sizeof(struct aesd_seekto)) != 0) {
                retval = -EFAULT;
            } else {
                PDEBUG("Calling ioctl seekto %d %d\n", seekto.write_cmd, seekto.write_cmd_offset);
                retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
                PDEBUG("Calling ioctl seekto %d %d\n", retval);
            }
            break;

        default:
            PDEBUG("Unknown command\n");
            break;
    }

    return retval;
}

struct file_operations aesd_fops = {
    .owner          = THIS_MODULE,
    .llseek         = aesd_llseek,
    .read           = aesd_read,
    .write          = aesd_write,
    .unlocked_ioctl = aesd_ioctl,
    .open           = aesd_open,
    .release        = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    PDEBUG("Allocating mem");
    aesd_device.data = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if (!aesd_device.data) {
        result = -ENOMEM;
        goto fail;
    }
    memset(aesd_device.data, 0, sizeof(struct aesd_circular_buffer));
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);
    if (result ) {
        PDEBUG("Unable to setup cdev %d %d\n", result, aesd_major);
        goto fail;
    }
    return 0;

fail:
    PDEBUG("Failed\n");
    unregister_chrdev_region(dev, 1);
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
