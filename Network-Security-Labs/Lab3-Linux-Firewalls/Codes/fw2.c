#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


static struct nf_hook_ops telnetFilterHook;

unsigned int telnetFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph=ip_hdr(skb);
    tcph = (void *)iph+iph->ihl*4;
    if(iph->protocol == IPPROTO_TCP)
    {
        if (tcph->dest == htons(23))
        {
            printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
                ((unsigned char *)&iph->daddr)[0],
                ((unsigned char *)&iph->daddr)[1],
                ((unsigned char *)&iph->daddr)[2],
                ((unsigned char *)&iph->daddr)[3]);
            return NF_DROP;
        }

        else if (tcph->source == htons(23))
        {
            printk(KERN_INFO "Dropping telnet packet from %d.%d.%d.%d\n",
                ((unsigned char *)&iph->saddr)[0],
                ((unsigned char *)&iph->saddr)[1],
                ((unsigned char *)&iph->saddr)[2],
                ((unsigned char *)&iph->saddr)[3]);
            return NF_DROP;
        }
    }
    else if (((((unsigned char *)&iph->daddr)[0] == 128)  && 
              (((unsigned char *)&iph->daddr)[1] == 230)  && 
              (((unsigned char *)&iph->daddr)[2] == 18)   && 
              (((unsigned char *)&iph->daddr)[3] == 198)) && 
              (iph->protocol == IPPROTO_TCP || 
                    iph->protocol == IPPROTO_UDP)) 
    {
      printk(KERN_INFO "Website at %d.%d.%d.%d is blocked\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}


int setUpFilter(void)
{
    printk(KERN_INFO "Registering a Filter\n");
    telnetFilterHook.hook = telnetFilter;
    telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
    telnetFilterHook.pf = PF_INET;
    telnetFilterHook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&telnetFilterHook);
    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "Filter is being removed\n");
    nf_unregister_hook(&telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");