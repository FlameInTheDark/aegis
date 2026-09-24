-- 0029 (down): drop the interface vendor column.
ALTER TABLE network_interfaces DROP COLUMN IF EXISTS vendor;
