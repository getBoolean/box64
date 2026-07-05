/* KurokoNX linker script for box64 on Horizon.
 *
 * Copy of devkitPro's $DEVKITPRO/libnx/switch.ld with ONE change: the `.rodata` output
 * section is folded into `.data.rel.ro` (the writable :data PT_LOAD) instead of the read-only
 * :rodata PT_LOAD.
 *
 * Why: box64 statically links newlib, whose const structures that embed pointers (__C_locale,
 * the dtoa/strtod tables, ctype tables, ...) land in `.rodata` and carry R_AARCH64_RELATIVE
 * relocations. libnx's crt0 (__nx_dynamic/_dynProcessRelr) applies those relocations with a
 * STORE at startup. In an NRO the rodata segment is mapped read-only on real hardware, so the
 * store faults (Data Abort, fault addr 0x0) before main() runs. Ryujinx doesn't enforce the RO
 * permission, so it "worked" only in the emulator. Putting the relocated data in the writable
 * data segment lets the relocations be applied. (Verified: 0 relocations target executable
 * .text, so making this data writable costs nothing but the RO protection on constants.)
 */
OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS
{
	code   PT_LOAD FLAGS(5) /* Read | Execute */;
	rodata PT_LOAD FLAGS(4) /* Read */;
	data   PT_LOAD FLAGS(6) /* Read | Write */;
	dyn    PT_DYNAMIC;
}

SECTIONS
{
	PROVIDE_HIDDEN( __start__ = 0x0 );

	/* =========== CODE section =========== */
	. = __start__;
	PROVIDE_HIDDEN( __code_start = . );

	.text :
	{
		KEEP (*(.crt0))
		*(.text.unlikely .text.*_unlikely .text.unlikely.*)
		*(.text.exit .text.exit.*)
		*(.text.startup .text.startup.*)
		*(.text.hot .text.hot.*)
		*(.text .stub .text.* .gnu.linkonce.t.*)
		. = ALIGN(8);
	} :code

	.init :
	{
		KEEP( *(.init) )
		. = ALIGN(8);
	} :code

	.plt :
	{
		*(.plt)
		*(.iplt)
		. = ALIGN(8);
	} :code

	.fini :
	{
		KEEP( *(.fini) )
		. = ALIGN(8);
	} :code

	/* =========== RODATA section =========== */
	. = ALIGN(0x1000);
	PROVIDE_HIDDEN( __rodata_start = . );

	.nx-module-name : { KEEP (*(.nx-module-name)) } :rodata

	.rela.dyn : { *(.rela.*) } :rodata
	.relr.dyn : { *(.relr.*) } :rodata

	.hash     : { *(.hash) } :rodata
	.gnu.hash : { *(.gnu.hash) } :rodata

	.dynsym   : { *(.dynsym) } :rodata
	.dynstr   : { *(.dynstr) } :rodata

	/* KUROKONX: `.rodata` intentionally NOT here — moved to `.data.rel.ro` below (writable). */

	.tls.align :
	{
		QUAD( MAX( ALIGNOF(.tdata), ALIGNOF(.tbss) ) )
	} :rodata

	PROVIDE_HIDDEN( __tls_align = ADDR(.tls.align) );

	.gcc_except_table  : { *(.gcc_except_table .gcc_except_table.*) } :rodata
	.eh_frame_hdr      : { *(.eh_frame_hdr) *(.eh_frame_entry .eh_frame_entry.*) } :rodata
	.eh_frame          : { KEEP (*(.eh_frame)) *(.eh_frame.*) } :rodata
	.gnu_extab         : { *(.gnu_extab*) } : rodata
	.exception_ranges  : { *(.exception_ranges .exception_ranges*) } :rodata

	PROVIDE_HIDDEN( __eh_frame_hdr_start = ADDR(.eh_frame_hdr)                         );
	PROVIDE_HIDDEN( __eh_frame_hdr_end   = ADDR(.eh_frame_hdr) + SIZEOF(.eh_frame_hdr) );

	.gnu.version       : { *(.gnu.version) } :rodata
	.gnu.version_d     : { *(.gnu.version_d) } :rodata
	.gnu.version_r     : { *(.gnu.version_r) } :rodata

	.note.gnu.build-id : { *(.note.gnu.build-id) } :rodata

	/* =========== RELRO section =========== */
	. = ALIGN(0x1000);
	PROVIDE_HIDDEN( __relro_start = . );

	.preinit_array :
	{
		PROVIDE_HIDDEN( __preinit_array_start = . );
		KEEP (*(.preinit_array))
		PROVIDE_HIDDEN( __preinit_array_end = . );
	} :data

	.init_array :
	{
		PROVIDE_HIDDEN( __init_array_start = . );
		KEEP( *(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)) )
		KEEP( *(.init_array .ctors) )
		PROVIDE_HIDDEN( __init_array_end = . );
	} :data

	.fini_array :
	{
		PROVIDE_HIDDEN( __fini_array_start = . );
		KEEP( *(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)) )
		KEEP( *(.fini_array .dtors) )
		PROVIDE_HIDDEN( __fini_array_end = . );
	} :data

	.data.rel.ro :
	{
		*(.data.rel.ro.local* .gnu.linkonce.d.rel.ro.local.*)
		*(.data.rel.ro .data.rel.ro.* .gnu.linkonce.d.rel.ro.*)
		/* KUROKONX: fold read-only data here so its R_AARCH64_RELATIVE relocations are applied
		   to WRITABLE pages at startup (see header comment). */
		*(.rodata .rodata.* .gnu.linkonce.r.*)
		. = ALIGN(8);
	} :data

	.dynamic : { *(.dynamic) } :data :dyn

	.got     : { *(.got) *(.igot) } :data
	.got.plt : { *(.got.plt)  *(.igot.plt) } :data

	PROVIDE_HIDDEN( __got_start__ = ADDR(.got)                        );
	PROVIDE_HIDDEN( __got_end__   = ADDR(.got.plt) + SIZEOF(.got.plt) );

	/* =========== DATA section =========== */
	. = ALIGN(0x1000);
	PROVIDE_HIDDEN( __data_start = . );

	.data :
	{
		*(.data .data.* .gnu.linkonce.d.*)
		SORT(CONSTRUCTORS)
		. = ALIGN(8);
	} :data

	.tdata :
	{
		*(.tdata .tdata.* .gnu.linkonce.td.*)
		. = ALIGN(8);
	} :data

	PROVIDE_HIDDEN( __tdata_lma     = ADDR(.tdata)                  );
	PROVIDE_HIDDEN( __tdata_lma_end = ADDR(.tdata) + SIZEOF(.tdata) );

	.tbss :
	{
		*(.tbss .tbss.* .gnu.linkonce.tb.*)
		*(.tcommon)
		. = ALIGN(8);
	} :data

	.bss :
	{
		*(.dynbss)
		*(.bss .bss.* .gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
	} :data

	/* Reserve space for the TLS segment of the main thread */
	.main.tls ALIGN(MAX(ALIGNOF(.tdata),ALIGNOF(.tbss))) :
	{
		. += SIZEOF(.tdata);
		. = ALIGN(ALIGNOF(.tbss));
		. += SIZEOF(.tbss);
	} :data

	PROVIDE_HIDDEN( __tls_start   = ADDR(.main.tls)                     );
	PROVIDE_HIDDEN( __tls_end     = ADDR(.main.tls) + SIZEOF(.main.tls) );

	PROVIDE_HIDDEN( __bss_start__ = ADDR(.bss) );
	PROVIDE_HIDDEN( __bss_end__   = __tls_end  );

	PROVIDE_HIDDEN( __end__ = . );

	/* =========== Argument buffer =========== */
	. = ALIGN(0x1000);
	PROVIDE_HIDDEN( __argdata__ = . );

	/* ==================
	   ==== Metadata ====
	   ================== */

	/* Discard sections that difficult post-processing */
	/DISCARD/ : { *(.group .comment .note) }

	/* Stabs debugging sections. */
	.stab          0 : { *(.stab) }
	.stabstr       0 : { *(.stabstr) }
	.stab.excl     0 : { *(.stab.excl) }
	.stab.exclstr  0 : { *(.stab.exclstr) }
	.stab.index    0 : { *(.stab.index) }
	.stab.indexstr 0 : { *(.stab.indexstr) }

	/* DWARF debug sections. */
	.debug          0 : { *(.debug) }
	.line           0 : { *(.line) }
	.debug_srcinfo  0 : { *(.debug_srcinfo) }
	.debug_sfnames  0 : { *(.debug_sfnames) }
	.debug_aranges  0 : { *(.debug_aranges) }
	.debug_pubnames 0 : { *(.debug_pubnames) }
	.debug_info     0 : { *(.debug_info) }
	.debug_abbrev   0 : { *(.debug_abbrev) }
	.debug_line     0 : { *(.debug_line) }
	.debug_frame    0 : { *(.debug_frame) }
	.debug_str      0 : { *(.debug_str) }
	.debug_loc      0 : { *(.debug_loc) }
	.debug_macinfo  0 : { *(.debug_macinfo) }
}
