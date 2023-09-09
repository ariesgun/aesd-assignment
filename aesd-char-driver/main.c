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

    *f_pos += entry->size;
    retval += entry->size;

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

    retval = count;

out:
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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
