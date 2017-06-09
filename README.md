# ARP

A very simple package with a single public function; `Sniff()`. Sniff takes a list of devices to listen for and a network interface. When a device makes an ARP request its `action` method is called.


## Example

```
package main

import (
	"fmt"

	"github.com/willis7/arp"
)

func Shout() {
	fmt.Println("Hello")
}

func main() {
	helloFn := arp.ActionerFunc(Shout)

	devs := []arp.Device{{"Hello", "ab:cd:ef:12:34:56", helloFn }}

	arp.Sniff(devs, "en0")
}
```

In the code above, when an ARP request is detected coming from mac address `ab:cd:ef:12:34:56` the `helloFn` `ActionFunc` is called which is a wrapper around `Shout`. Hello simply prints `Hello` to stdout.


## Credit

*  https://github.com/chrisgilbert/godash
