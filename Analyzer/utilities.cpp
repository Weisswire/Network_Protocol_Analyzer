#include "pch.h"
#include "utilities.h"

/*pktΪ�����в���İ���dataΪҪ��Ϊ�����ϵ�����*/

/*ֻ���÷�����·�㺯������ʵ�ֲ�����*/

/*������·��*/
int analyze_frame(const u_char * pkt, struct datapkt * data, struct pktcount * npacket)      //��pkt���������յ����ֽ������ݣ�������ݴ���data�����ػ���
{
	int i;
	struct ethhdr *ethh = (struct ethhdr*)pkt;                                               //ָ��ǿת֮����Ը�ֵ
	                                                                                         //��ֵ֮����԰����Լ�д�����ݽṹ�����ֽ��е���
	data->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
	if (NULL == data->ethh)
		return -1;

	for (i = 0; i < 6; i++)
	{
		data->ethh->dest[i] = ethh->dest[i];
		data->ethh->src[i] = ethh->src[i];
	}

	npacket->n_sum++;

	/*���������ֽ�˳��ԭ����Ҫ�Խ���ntohs*/
	data->ethh->type = ntohs(ethh->type);                          //��һ��16λ���������ֽ�˳��ת��Ϊ�����ֽ�˳��

	//����ARP����IP��
	switch (data->ethh->type)
	{
	case 0x0806:
		return analyze_arp((u_char*)pkt + 14, data, npacket);      //MAC֡ͷ��СΪ14��֮��Ϊ�����
		break;
	case 0x0800:
		return analyze_ip((u_char*)pkt + 14, data, npacket);
		break;
	case 0x86dd:
		return analyze_ip6((u_char*)pkt + 14, data, npacket);
		//return -1;
		break;
	default:
		npacket->n_other++;
		return -1;
		break;
	}
	//free(ethh);
	return 1;
}

/*��������㣺ARP*/
int analyze_arp(const u_char* pkt, datapkt *data, struct pktcount *npacket)       //�˴���pkt��Ų����14�ֽڵ�������ײ�
{
	int i;
	struct arphdr *arph = (struct arphdr*)pkt;
	data->arph = (struct arphdr*)malloc(sizeof(struct arphdr));

	if (NULL == data->arph)
		return -1;

	//����IP��MAC
	for (i = 0; i < 6; i++)
	{
		if (i < 4)
		{
			data->arph->ar_destip[i] = arph->ar_destip[i];
			data->arph->ar_srcip[i] = arph->ar_srcip[i];
		}
		data->arph->ar_destmac[i] = arph->ar_destmac[i];
		data->arph->ar_srcmac[i] = arph->ar_srcmac[i];
	}

	data->arph->ar_hln = arph->ar_hln;
	data->arph->ar_hrd = ntohs(arph->ar_hrd);
	data->arph->ar_op = ntohs(arph->ar_op);
	data->arph->ar_pln = arph->ar_pln;
	data->arph->ar_pro = ntohs(arph->ar_pro);

	strcpy_s(data->pktType, "ARP");
	npacket->n_arp++;
	//free(arph);
	return 1;
}

/*��������㣺IP*/
int analyze_ip(const u_char* pkt, datapkt *data, struct pktcount *npacket)            //�˴���pkt�Ѿ���Ų��14���ֽڵ�������ײ�
{
	struct iphdr *iph = (struct iphdr*)pkt;
	data->iph = (struct iphdr*)malloc(sizeof(struct iphdr));

	if (NULL == data->iph)
		return -1;
	data->iph->check = iph->check;
	npacket->n_ip++;

	
	data->iph->saddr = iph->saddr;
	data->iph->daddr = iph->daddr;

	data->iph->frag_off = iph->frag_off;
	data->iph->id = iph->id;
	data->iph->proto = iph->proto;
	data->iph->tlen = ntohs(iph->tlen);
	data->iph->tos = iph->tos;
	data->iph->ttl = iph->ttl;
	data->iph->ihl = iph->ihl;
	data->iph->version = iph->version;
	data->iph->op_pad = iph->op_pad;

	int iplen = iph->ihl * 4;							//ipͷ����
	switch (iph->proto)
	{
	case PROTO_ICMP:
		return analyze_icmp((u_char*)iph + iplen, data, npacket);
		break;
	case PROTO_TCP:
		return analyze_tcp((u_char*)iph + iplen, data, npacket);
		break;
	case PROTO_UDP:
		return analyze_udp((u_char*)iph + iplen, data, npacket);
		break;
	default:
		return-1;
		break;
	}
	//free(iph);
	return 1;
}

/*��������㣺IPv6*/
int analyze_ip6(const u_char* pkt, datapkt *data, struct pktcount *npacket)
{
	int i;
	struct iphdr6 *iph6 = (struct iphdr6*)pkt;
	data->iph6 = (struct iphdr6*)malloc(sizeof(struct iphdr6));

	if (NULL == data->iph6)
		return -1;

	npacket->n_ip6++;

	data->iph6->version = iph6->version;
	data->iph6->flowtype = iph6->flowtype;
	data->iph6->flowid = iph6->flowid;
	data->iph6->plen = ntohs(iph6->plen);
	data->iph6->nh = iph6->nh;
	data->iph6->hlim = iph6->hlim;

	for (i = 0; i < 16; i++)
	{
		data->iph6->saddr[i] = iph6->saddr[i];
		data->iph6->daddr[i] = iph6->daddr[i];
	}

	switch (iph6->nh)
	{
	case 0x3a:
		return analyze_icmp6((u_char*)iph6 + 40, data, npacket);
		break;
	case 0x06:
		return analyze_tcp((u_char*)iph6 + 40, data, npacket);
		break;
	case 0x17:
		return analyze_udp((u_char*)iph6 + 40, data, npacket);
		break;
	default:
		return-1;
		break;
	}
	
	strcpy(data->pktType,"IPv6");
	//free(iph6);
	return 1;
}

/*��������㣺ICMP*/
int analyze_icmp(const u_char* pkt, datapkt *data, struct pktcount *npacket)
{
	struct icmphdr* icmph = (struct icmphdr*)pkt;
	data->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

	if (NULL == data->icmph)
		return -1;

	data->icmph->chksum = icmph->chksum;
	data->icmph->code = icmph->code;
	data->icmph->type = icmph->type;
	strcpy_s(data->pktType, "ICMP");
	npacket->n_icmp++;
	//free(icmph);
	return 1;
}

/*��������㣺ICMPv6*/
int analyze_icmp6(const u_char* pkt, datapkt *data, struct pktcount *npacket)
{
	struct icmphdr6* icmph6 = (struct icmphdr6*)pkt;
	data->icmph6 = (struct icmphdr6*)malloc(sizeof(struct icmphdr6));

	if (NULL == data->icmph6)
		return -1;

	data->icmph6->chksum = icmph6->chksum;
	data->icmph6->code = icmph6->code;
	data->icmph6->type = icmph6->type;
	strcpy_s(data->pktType, "ICMPv6");
	//npacket->n_icmp6++;
	//free(icmph6);
	return 1;
}

/*��������㣺TCP*/
int analyze_tcp(const u_char* pkt, datapkt *data, struct pktcount *npacket)
{
	struct tcphdr *tcph = (struct tcphdr*)pkt;
	data->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	if (NULL == data->tcph)
		return -1;

	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;

	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;
	//data->tcph->doff_flag = tcph->doff_flag;

	data->tcph->dport = ntohs(tcph->dport);
	data->tcph->seq = tcph->seq;
	data->tcph->sport = ntohs(tcph->sport);
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window = tcph->window;
	data->tcph->opt = tcph->opt;

	/////////////////////*http��֧*/////////////////////////
	if (ntohs(tcph->dport) == 80 || ntohs(tcph->sport) == 80)         //�������˿�Ϊ80��ΪHTTP
	{
		npacket->n_http++;
		npacket->n_tcp++;
		strcpy_s(data->pktType, "HTTP");
	}
	else if (ntohs(tcph->dport) == 143 || ntohs(tcph->sport) == 143)         //�������˿�Ϊ143��ΪIMAP
	{
		npacket->n_http++;
		npacket->n_tcp++;
		strcpy_s(data->pktType, "IMAP");
	}
	else if (ntohs(tcph->dport) == 25 || ntohs(tcph->sport) == 25)         //�������˿�Ϊ25��ΪSMTP
	{
		npacket->n_http++;
		npacket->n_tcp++;
		strcpy_s(data->pktType, "SMTP");
	}
	else {
		npacket->n_tcp++;
		strcpy_s(data->pktType, "TCP");
	}
	//free(tcph);
	return 1;
}

/*��������㣺UDP*/
int analyze_udp(const u_char* pkt, datapkt *data, struct pktcount *npacket)
{
	struct udphdr* udph = (struct udphdr*)pkt;
	data->udph = (struct udphdr*)malloc(sizeof(struct udphdr));
	if (NULL == data->udph)
		return -1;

	data->udph->check = udph->check;
	data->udph->dport = ntohs(udph->dport);
	data->udph->len = ntohs(udph->len);
	data->udph->sport = ntohs(udph->sport);
	if (ntohs(udph->dport) == 53 || ntohs(udph->sport) == 53)         //�������˿�Ϊ53��ΪDNS
	{
		npacket->n_dns++;
		npacket->n_udp++;
		strcpy_s(data->pktType, "DNS");
	}
	else if(ntohs(udph->dport) == 8000 || ntohs(udph->sport) == 8000)         //�������˿�Ϊ8000��ΪOICQ
	{
		npacket->n_udp++;
		strcpy_s(data->pktType, "OICQ");
	}
	else {
		npacket->n_udp++;
		strcpy_s(data->pktType, "UDP");
	}

	//strcpy_s(data->pktType, "UDP");
	//npacket->n_udp++;
	//free(udph);
	return 1;
}

//�����ݰ���ʮ�����Ʒ�ʽ��ӡ����
void print_packet_hex(const u_char* pkt, int size_pkt, CString *buf)
{
	int i = 0, j = 0, rowcount;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf, 0, 256);

	for (i = 0; i < size_pkt; i += 16)                             //ÿ��ÿ��16�ֽڣ�i��������ţ��ڼ����ֽڣ�
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)pkt[i + j]);    //�޷���int��16�������������׽���ľ��Ƕ����Ʊ�������

		//����16���ÿո���
		if (rowcount < 16)
		{
			for (j = rowcount; j < 16; j++)
				buf->AppendFormat(_T("     "));
		}
		
		//C �⺯�� int isprint(int c) ����������ַ��Ƿ��ǿɴ�ӡ�ġ��ɴ�ӡ�ַ��Ƿǿ����ַ����ַ���
		for (j = 0; j < rowcount; j++)
		{
			ch = pkt[i + j];                                       //int��ASCII���תΪchar���
			ch = isprint(ch) ? ch : '.';                           //����Ƿ����print����������ʾ����.����
			buf->AppendFormat(_T("%c"), ch);
		}

		buf->Append(_T("\r\n"));                                   //windowsϵͳ�»�����\r\n

		if (rowcount < 16)
			return;
	}
}

