#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xaaa11587, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xea21ecf9, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0x3e02dbe7, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0xb4adbe6a, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0xecf3e2fd, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xcfb6211d, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0x8025cd06, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3499AD071378A48C7E08AD2");
