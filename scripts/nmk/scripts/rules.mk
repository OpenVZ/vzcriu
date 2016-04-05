ifndef ____nmk_defined__rules

#
# Accumulate common flags.
define nmk-ccflags
        $(CFLAGS) $(ccflags-y) $(CFLAGS_$(@F))
endef

define nmk-asflags
        $(CFLAGS) $(ASFLAGS) $(asflags-y) $(AFLAGS_$(@F))
endef

#
# General rules.
define gen-rule-o-from-c-by-name
$(1).o: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
endef
define gen-rule-i-from-c-by-name
$(1).i: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
endef
define gen-rule-s-from-c-by-name
$(1).s: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -S -fverbose-asm $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
endef
define gen-rule-o-from-S-by-name
$(1).o: $(2).S $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-asflags)) $(4) $$< -o $$@
endef
define gen-rule-d-from-c-by-name
$(1).d: $(2).c $(3)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
endef
define gen-rule-d-from-S-by-name
$(1).d: $(2).S $(3)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-asflags)) $(4) $$< -o $$@
endef
define gen-rule-i-from-S-by-name
$(1).i: $(2).S $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-asflags)) $(4) $$< -o $$@
endef

#
# Expand early which matched all implicits.
$(eval $(call gen-rule-o-from-c-by-name,%,%))
$(eval $(call gen-rule-i-from-c-by-name,%,%))
$(eval $(call gen-rule-s-from-c-by-name,%,%))
$(eval $(call gen-rule-o-from-S-by-name,%,%))
$(eval $(call gen-rule-d-from-c-by-name,%,%))
$(eval $(call gen-rule-d-from-S-by-name,%,%))
$(eval $(call gen-rule-i-from-S-by-name,%,%))

#
# Footer.
$(__nmk_dir)scripts/rules.mk:
	@true
____nmk_defined__rules = y
endif
