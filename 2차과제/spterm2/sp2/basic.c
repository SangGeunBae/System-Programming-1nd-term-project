// yong woo kim, sang geun bae 2019.10.30
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netpoll.h>


#define PROC_DIRNAME "myproc"
#define PROC_FILENAME "myproc"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

static int pnum = 1;

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static unsigned int my_hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	printk(KERN_INFO "PRE_ROUTING[(%d ; %d ; %d ; %d.%d.%d.%d ; %d.%d.%d.%d)]\n",ih->protocol, htons(th->source), htons(th->dest), NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));
	if(htons(th->source)==3333){
		th->dest=htons(pnum);
		th->source=htons(pnum);
		ih->daddr=0x6938a8c0;
		}

	return NF_ACCEPT;
}

static unsigned int my_hook_fn2(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	printk(KERN_INFO "FORWARD[(%d ; %d ; %d ; %d.%d.%d.%d ; %d.%d.%d.%d)]\n",ih->protocol, htons(th->source), htons(th->dest), NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));
	return NF_ACCEPT;
}

static unsigned int my_hook_fn3(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	printk(KERN_INFO "POST_ROUTING[(%d ; %d ; %d ; %d.%d.%d.%d ; %d.%d.%d.%d)]\n",ih->protocol, htons(th->source), htons(th->dest), NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));
	return NF_ACCEPT;
}

static struct nf_hook_ops my_nf_ops; //pre routing
static struct nf_hook_ops my_nf_ops2; //forward 
static struct nf_hook_ops my_nf_ops3; //post routing


static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Simple Module Open!!\n");

	return 0;
}
static ssize_t my_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{
	printk(KERN_INFO "Simple Module Write!! %s\n", user_buffer);

	return count;
}

static const struct file_operations myproc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_write,
};

static int hello_init(void)
{
	printk(KERN_INFO "Simple Module Init!!\n");
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file = proc_create(PROC_FILENAME, 0600, proc_dir, &myproc_fops);

	my_nf_ops.hook=my_hook_fn;
	my_nf_ops.pf=PF_INET;
	my_nf_ops.hooknum=NF_INET_PRE_ROUTING;
	my_nf_ops.priority=NF_IP_PRI_FIRST;

	my_nf_ops2.hook=my_hook_fn2;
	my_nf_ops2.pf=PF_INET;
	my_nf_ops2.hooknum=NF_INET_FORWARD;
	my_nf_ops2.priority=NF_IP_PRI_FIRST;

	my_nf_ops3.hook=my_hook_fn3;
	my_nf_ops3.pf=PF_INET;
	my_nf_ops3.hooknum=NF_INET_POST_ROUTING;
	my_nf_ops3.priority=NF_IP_PRI_FIRST;

	nf_register_hook(&my_nf_ops);
	nf_register_hook(&my_nf_ops2);
	nf_register_hook(&my_nf_ops3);
	return 0;
}
static void hello_exit(void)
{
	nf_unregister_hook(&my_nf_ops);
	nf_unregister_hook(&my_nf_ops2);
	nf_unregister_hook(&my_nf_ops3);
	printk(KERN_INFO "Module exit\n");
}

module_param(pnum, int, 0);
module_init(hello_init);
module_exit(hello_exit);


MODULE_AUTHOR("BSG");
MODULE_DESCRIPTION("It's Simple");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
