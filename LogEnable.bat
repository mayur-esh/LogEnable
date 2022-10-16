:: Work based on a lot of good work from -
:: https://ossemproject.com/dm/mitre_attack/attack_ds_events_mappings.html
:: https://success.qualys.com/support/s/article/000003170
:: 
:: Run with local Administrator or SYSTEM privileges.
:: Log sizes converted:
:: 128 MB: 134217728kb
:: 256 MB: 268435456kb
:: 512 MB: 536870912kb
:: 1 GB: 1073741824kb

Auditpol /get /category:* > AuditPol_BEFORE_%TIME%.txt