
// AnalyzerDlg.h: 头文件


#pragma once
#include "pcap.h"
#include "Protocol.h"
#include "utilities.h"
#include "afxcmn.h"
#include "afxwin.h"



// CAnalyzerDlg 对话框
class CAnalyzerDlg : public CDialogEx
{
// 构造
public:
	CAnalyzerDlg(CWnd* pParent = nullptr);	   //标准构造函数

	/*功能函数*/
	int ProtocolAnalyze_initCap();
	int ProtocolAnalyze_startCap();
	int ProtocolAnalyze_updateTree(int index);
	int ProtocolAnalyze_updateEdit(int index);
	int ProtocolAnalyze_updateNPacket();
	int ProtocolAnalyze_saveFile();
	int ProtocolAnalyze_readFile(CString path);

	/*数据部分*/
	int devCount;
	struct pktcount npacket;				    //各类数据包计数
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;                          //保存网卡基本信息的类型。通常用指针来使用
	pcap_if_t *dev;
	pcap_t *adhandle;                           //捕获的数据包用
	pcap_dumper_t *dumpfile;                    //下载文件（存到SavedData下）
	char filepath[512];							//文件保存路径
	char filename[64];							//文件名称							

	HANDLE m_ThreadHandle;			            //线程句柄

	CPtrList m_pktList;							//捕获包所存放的链表

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ANALYZER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton5();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	CListCtrl m_listCtrl;
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CEdit m_edit;
	CButton m_buttonStart;
	CButton m_buttonStop;
	CPtrList m_localDataList;				//保存被本地化后的数据包（链表）
	CPtrList m_netDataList;					//保存从网络中直接获取的数据包（链表）
	CBitmapButton m_bitButton;		        //图片按钮
	int npkt;                               //用于列表序号
	float m_PacketsLen;                     //接受包的总长度
	float Traffic;                          //用来计算流量
	CEdit m_editNTcp;
	CEdit m_editNUdp;
	CEdit m_editNIcmp;
	CEdit m_editNIpv6;
	CEdit m_editNArp;
	CEdit m_editNHttp;
	CEdit m_editNOther;
	CEdit m_editNSum;
	CEdit m_Traffic;
	CButton m_buttonSave;                   //为按钮起个名字方便之后使用
	CButton m_buttonRead;
	CEdit m_editNIpv4;
	CEdit m_editNDns;
	afx_msg void OnColumnclickList1(NMHDR *pNMHDR, LRESULT *pResult);  //列表头点击事件
};
