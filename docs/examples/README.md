# f5_bigip Collection Examples

This is a set of examples for demonstrating the use of the f5_bigip collection. This collection is primarily focused on leveraging F5's declarative APIs to provision BIG-IP and BIG-IQ. There will still be a some operational modules included such as config save, backup, policy upload, etc.


### Notes

* The majority of the example folders will reference inventory and host_vars within this parent directory for consistency.
* Both the new **HTTPAPI** connection variables and the previous **Provider** variables are included in the host_vars for reference. The majority of modules within the **f5_bigip** collection do not require **Provider** anymore as they use the **HTTPAPI** standard instead.

### Examples

* [AS3 Basics](as3_basics/)
* [TS Basics](ts_basics/)
* [DO Basics](do_basics/)
* [Create an app with f5_modules vs f5_bigip](f5_modules-f5_bigip-comparison/)