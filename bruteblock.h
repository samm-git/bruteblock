/* */

/* Note: ipfw_optval_t is an argument of ipfw command as X below.
 *   # ipfw table add ipfw2_table_no X
 * where X is an unsigned 32bits.
 * To get correct time diff based on the ipfw's optional value as X,
 * do not calculate with time() directly.  This type may be changed in
 * the future *BSD. Change types below if it is the case.
 * See also 'struct table_xentry' in /usr/src/sys/netpfil/ipfw/ip_fw_table.c
 */
typedef u_int32_t ipfw_optval_t;
typedef int32_t s_ipfw_optval_t;
#define	FMT_IPFW_OPTVAL	"%ud"

int delete_host(const char *host, int prefixlen, ipfw_optval_t exptime);
int ipfw_table_handler(int ac, char *av[]);

extern int ipfw2_table_no;

#define IPFW_CMD_TABLE	"table"
#define IPFW_CMD_TABLE_ADD	"add"
#define IPFW_CMD_TABLE_DEL	"delete"
#define IPFW_CMD_TABLE_LIST	"list"

/* end of file */
