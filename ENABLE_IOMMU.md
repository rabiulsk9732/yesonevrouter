# How to Enable IOMMU for DPDK vfio-pci

## Current Status
IOMMU is **NOT enabled**. This is why vfio-pci cannot bind to the e1000e devices.

## Steps to Enable IOMMU

### 1. Kernel Parameters Added
I've already added the following to `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"
```

### 2. Update GRUB (Already Done)
```bash
update-grub
```

### 3. **REBOOT REQUIRED**
You **MUST reboot** for IOMMU to be enabled:
```bash
reboot
```

### 4. After Reboot, Verify IOMMU is Enabled
```bash
# Check kernel command line
cat /proc/cmdline | grep iommu

# Check IOMMU groups exist
ls /sys/kernel/iommu_groups/

# Check dmesg for IOMMU
dmesg | grep -i iommu
```

### 5. Bind Devices to vfio-pci
After reboot, the devices should bind successfully:
```bash
# Unbind from kernel driver
dpdk-devbind.py --unbind 0000:00:13.0 0000:00:14.0

# Bind to vfio-pci
dpdk-devbind.py --bind=vfio-pci 0000:00:13.0 0000:00:14.0

# Verify
dpdk-devbind.py --status
```

### 6. Start yesrouter
```bash
systemctl start yesrouter
yesrouterctl show interfaces brief
```

## Important Notes

### For VMs (QEMU/KVM/Proxmox)
**CRITICAL:** If this is a VM, you **MUST** enable IOMMU at the **hypervisor level** as well!

**Proxmox VE:**
1. Enable IOMMU on the **host** (Proxmox):
   - Edit `/etc/default/grub` on Proxmox host
   - Add: `GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"`
   - Run `update-grub` and reboot the Proxmox host
   
2. Enable PCI passthrough for the VM:
   - In Proxmox web UI: VM → Hardware → Add → PCI Device
   - Select your network cards (0000:00:13.0, 0000:00:14.0)
   - Enable "All Functions" and "ROM-Bar" if needed
   - Set "Primary GPU" to No

3. **Alternative:** Use SR-IOV if your NICs support it (better performance)

**QEMU/KVM (direct):**
- Add `-device intel-iommu,intremap=on` to QEMU command line
- Or in libvirt XML: `<iommu model='intel'/>`

**VMware:**
- Enable "Virtualize Intel VT-x/EPT or AMD-V/RVI" in VM settings
- Enable "Virtualize IOMMU (Intel VT-d)" in VM settings

**VirtualBox:**
- Enable "Enable I/O APIC" and "Enable VT-x/AMD-V" in VM settings
- Note: VirtualBox has limited IOMMU support

### Known Issues from Proxmox Forum
According to [Proxmox forum discussions](https://forum.proxmox.com/tags/dpdk/), error -22 with vfio-pci is commonly caused by:
1. **IOMMU not enabled at hypervisor level** (most common)
2. **PCI passthrough not properly configured** in VM settings
3. **Device already in use** by another driver or process
4. **Hardware not supporting IOMMU** (rare, but possible)

### Alternative: Use igb_uio Driver
If IOMMU cannot be enabled, you can use `igb_uio` driver instead:
1. Build DPDK with `igb_uio` driver
2. Load the driver: `modprobe igb_uio`
3. Bind devices: `dpdk-devbind.py --bind=igb_uio 0000:00:13.0 0000:00:14.0`

## Current Configuration
- Devices: Intel 82574L (e1000e) at 0000:00:13.0 and 0000:00:14.0
- Kernel driver: e1000e (currently unbound)
- Target DPDK driver: vfio-pci (requires IOMMU)

