
// AnalyzerDlg.cpp: 实现文件
//
//#define _CRT_SECURE_NO_WARNINGS
//#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pch.h"
#include "framework.h"
#include "Analyzer.h"
#include "AnalyzerDlg.h"
#include "afxdialogex.h"

//下面2行是为了列表排序
DWORD dwSelColID = 0;  //选择的列
BOOL bASC = FALSE;     //是否升序

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
DWORD WINAPI ProtocolAnalyze_CapThread(LPVOID lpParameter);          //声明创建线程的函数，因为在定义之前要用到故提前声明

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAnalyzerDlg 对话框



CAnalyzerDlg::CAnalyzerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ANALYZER_DIALOG, pParent)
{
	//m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);             //图标
}

//框体与名字的联系
void CAnalyzerDlg::DoDataExchange(CDataExchange* pDX)           
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_EDIT2, m_editNTcp);
	DDX_Control(pDX, IDC_EDIT3, m_editNUdp);
	DDX_Control(pDX, IDC_EDIT4, m_editNIcmp);
	DDX_Control(pDX, IDC_EDIT5, m_editNIpv6);
	DDX_Control(pDX, IDC_EDIT6, m_editNArp);
	DDX_Control(pDX, IDC_EDIT7, m_editNHttp);
	DDX_Control(pDX, IDC_EDIT8, m_editNOther);
	DDX_Control(pDX, IDC_EDIT9, m_editNSum);
	DDX_Control(pDX, IDC_BUTTON5, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonRead);
	DDX_Control(pDX, IDC_EDIT10, m_editNIpv4);
	DDX_Control(pDX, IDC_EDIT11, m_editNDns);
}

//按钮操作与函数联系
BEGIN_MESSAGE_MAP(CAnalyzerDlg, CDialogEx)                                     
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	ON_BN_CLICKED(IDC_BUTTON1, &CAnalyzerDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CAnalyzerDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON4, &CAnalyzerDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &CAnalyzerDlg::OnBnClickedButton5)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CAnalyzerDlg::OnLvnItemchangedList1)  //某个项已经发生变化，选中某个项
	//ON_NOTIFY(LVN_HOTTRACK, IDC_LIST1, &CAnalyzerDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CAnalyzerDlg::OnNMCustomdrawList1)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST1, &CAnalyzerDlg::OnColumnclickList1)
END_MESSAGE_MAP()


// CAnalyzerDlg 消息处理程序

//初始化窗口
BOOL CAnalyzerDlg::OnInitDialog()                                                
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0, _T("编号"), 3, 50);                        //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1, _T("时间"), 3, 160);
	m_listCtrl.InsertColumn(2, _T("长度"), 3, 72);
	m_listCtrl.InsertColumn(3, _T("源MAC地址"), 3, 160);
	m_listCtrl.InsertColumn(4, _T("目的MAC地址"), 3, 160);
	m_listCtrl.InsertColumn(5, _T("协议类型"), 3, 90);
	m_listCtrl.InsertColumn(6, _T("源IP地址"), 3, 145);
	m_listCtrl.InsertColumn(7, _T("目的IP地址"), 3, 145);
	m_listCtrl.InsertColumn(8, _T("备注"), 3, 145);

	m_comboBox.AddString(_T("请选择一个网卡接口(必选)"));
	m_comboBoxRule.AddString(_T("请选择过滤规则(可选)"));

	if (ProtocolAnalyze_initCap() < 0)
		return FALSE;

	/*初始化接口列表*/
	for (dev = alldev; dev; dev = dev->next)
	{
		if (dev->description)
			m_comboBox.AddString(CString(dev->description));  
	}

	/*初始化过滤规则列表*/
	m_comboBoxRule.AddString(_T("arp"));
	m_comboBoxRule.AddString(_T("ip"));
	
	m_comboBoxRule.AddString(_T("icmp"));
	
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("tcp"));
	
	

	m_comboBox.SetCurSel(0);                     //初始选择置为0
	m_comboBoxRule.SetCurSel(0);

	m_buttonStop.EnableWindow(FALSE);            //禁用停止捕获和保存按钮
	m_buttonSave.EnableWindow(FALSE);
   
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAnalyzerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAnalyzerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAnalyzerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


/*----------------------------------------*事件函数*------------------------------------------*/


/*开始按钮*/
void CAnalyzerDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	//如果已经有数据了，提示保存数据
	if (this->m_localDataList.IsEmpty() == FALSE)
	{
		if (MessageBox(_T("确认不保存数据？"), _T("警告"), MB_YESNO) == IDNO)     //不确认不保存则进入保存程序
		{
			this->ProtocolAnalyze_saveFile();
		}
	}

	this->npkt = 1;													//重新计数
	this->m_localDataList.RemoveAll();				                //每次一开始就将以前存的数据清空掉
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket), 0, sizeof(struct pktcount));           //初始化计数
	this->ProtocolAnalyze_updateNPacket();

	if (this->ProtocolAnalyze_startCap() < 0)
		return;
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowText(_T(""));                             //报文内容显示框置空
	this->m_buttonStart.EnableWindow(FALSE);                        //按下开始捕获之后，可以使用停止捕获按键，不可以使用开始捕获和保存按键
	this->m_buttonStop.EnableWindow(TRUE);
	this->m_buttonSave.EnableWindow(FALSE);
}

/*结束按钮*/
void CAnalyzerDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	if (NULL == this->m_ThreadHandle)
		return;
	if (TerminateThread(this->m_ThreadHandle, -1) == 0)
	{
		MessageBox(_T("关闭线程错误，请稍后重试"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_buttonStart.EnableWindow(TRUE);                        //按下结束捕获按钮后，可以使用开始捕获按钮和保存按钮，不可以使用结束捕获按钮
	this->m_buttonStop.EnableWindow(FALSE);
	this->m_buttonSave.EnableWindow(TRUE);
}

/*读取按钮*/
void CAnalyzerDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	//读取之前将ListCtrl清空
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowText(_T(""));
	this->npkt = 1;													//列表重新计数
	this->m_localDataList.RemoveAll();				                //每次一开始就将以前存的数据清空掉
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket), 0, sizeof(struct pktcount));           //各类包计数清空

	//打开文件对话框
	//TCHAR szFilter[] = _T("数据包(*.pcap;*.cap)\0*.pcap;*.cap\0All Files\0*.*\0\0");
	
	CFileDialog   FileDlg(TRUE, _T(".pcap") , NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("常用数据包格式文件(*.pcap;*.cap;*.pcapng)|*.pcap;*.cap;*.pcapng| All Files (*.*) |*.*||"), NULL);
	//FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");                             //打开文件的其实检索位置，默认在桌面
	FileDlg.m_ofn.lpstrTitle = _T("打开文件");

	//FileDlg.m_ofn.lpstrFilter = szFilter;

	if (FileDlg.DoModal() == IDOK)
	{
		int ret = this->ProtocolAnalyze_readFile(FileDlg.GetPathName());
		if (ret < 0)              //打开文件出现错误会return -1
			return;
	}
}

/*保存按钮*/
void CAnalyzerDlg::OnBnClickedButton5()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->ProtocolAnalyze_saveFile() < 0)      //遇到错误会return -1
		return;
}

/*点击列表内容更新一次数据统计和树形控件*/
void CAnalyzerDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	int index;
	index = this->m_listCtrl.GetHotItem();                                   // 当前检索列表视图项在光标之下


	if (index > this->m_localDataList.GetCount() - 1)
		return;

	this->ProtocolAnalyze_updateEdit(index);
	this->ProtocolAnalyze_updateTree(index);
	*pResult = 0;
}

//改变ListCtrl每行颜色，ListCtrl在插入一个Item的时候，会发送一个NM_CUSTOMDRAW的消息，我们只要实现这个消息响应函数，并在里面绘制我们的颜色就可以了。
void CAnalyzerDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) {
		COLORREF crText;
		char buf[10];
		memset(buf, 0, 10);
		POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);                //获取由一个索引（从零开始）指定的元素的位置
		struct datapkt * local_data = (struct datapkt *)this->m_localDataList.GetAt(pos);      //获取在给定位置的元素
		strcpy(buf, local_data->pktType);

		if (strcmp(buf, "IPv6") == 0)
			crText = RGB(238, 232, 180);/*(111, 224, 254);*/
		else if (strcmp(buf, "UDP") == 0)
			crText = RGB(194, 195, 252);
		else if (strcmp(buf, "TCP") == 0)
			crText = RGB(249, 204, 226);/*(230, 230, 230);*/
		else if (strcmp(buf, "ARP") == 0)
			crText = RGB(169, 238, 175);/*(226, 238, 227);*/
		else if (strcmp(buf, "ICMP") == 0)
			crText = RGB(49, 164, 238);
		else if (strcmp(buf, "HTTP") == 0)
			crText = RGB(147, 232, 254);/*(238, 232, 180);*/
		else if (strcmp(buf, "ICMPv6") == 0)
			crText = RGB(189, 254, 76);
		else if (strcmp(buf, "DNS") == 0)
			crText = RGB(244, 192, 184);
		else if (strcmp(buf, "OICQ") == 0)
			crText = RGB(236, 236, 236);
		else if (strcmp(buf, "SMTP") == 0)
			crText = RGB(7, 189, 169);
		else if (strcmp(buf, "IMAP") == 0)
			crText = RGB(255, 179, 64);

		pNMCD->clrTextBk = crText;
		*pResult = CDRF_DODEFAULT;
	}
}



/*----------------------------------------*功能函数*-------------------------------------------*/



//初始化winpcap
int CAnalyzerDlg::ProtocolAnalyze_initCap()
{
	devCount = 0;
	if (pcap_findalldevs(&alldev, errbuf) == -1)
		return -1;
	for (dev = alldev; dev; dev = dev->next)
		devCount++;
	return 0;
}

/*开始捕获*/
int CAnalyzerDlg::ProtocolAnalyze_startCap()
{
	int if_index, filter_index, count;
	u_int netmask;
	struct bpf_program fcode;

	ProtocolAnalyze_initCap();   //初始化winpcap

	//获得接口和过滤器索引
	if_index = this->m_comboBox.GetCurSel();
	filter_index = this->m_comboBoxRule.GetCurSel();

	if (0 == if_index || CB_ERR == if_index)         //选中内容为空或没有指定内容被选中时，返回的Message提示未选择网卡接口
	{
		MessageBox(_T("请选择一个合适的网卡接口！"));
		return -1;
	}
	if (CB_ERR == filter_index)                      //没有指定内容被选中时返回CB_ERR，因此可以根据返回值来确定是否有项目被选中
	{
		MessageBox(_T("过滤器选择错误！"));
		return -1;
	}

	/*获得选中的网卡接口*/
	dev = alldev;
	for (count = 0; count < if_index - 1; count++)      //遍历
		dev = dev->next;

	if ((adhandle = pcap_open_live(dev->name,	        // 设备名
		65536,											// 捕获数据包的最大数目																					
		1,											    // 混杂模式 (非0意味着是混杂模式)
		1000,										    // 读超时设置
		errbuf											// 错误信息
	)) == NULL)
	{
		MessageBox(_T("无法打开接口：" + CString(dev->description)));
		/*释放设备列表*/
		pcap_freealldevs(alldev);
		return -1;
	}

	/*检查是否为以太网*/
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		MessageBox(_T("本系统不适合于非以太网的网络!"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if (dev->addresses != NULL)
		/*获得第一个地址的掩码*/
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	    /*如果接口没有地址，那么我们假设一个C类的地址*/
	else
		netmask = 0xffffff;


	//设置过滤器要用到两个函数，一个是pcap_compile()，另一个是pcap_setfilter()
	//编译过滤器
	if (0 == filter_index)                                                   //若未选择过滤器，则默认选择"ip or arp"
	{
		char filter[] = "ip or arp";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)          //检查已选择的过滤器
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}
	else if (4 == filter_index)                                                   //bug排查:若选择udp过滤器，则默认选择"ip and udp"
	{
		char filter[] = "ip and udp";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)               //检查已选择的过滤器
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}
	else if (5 == filter_index)                                                   //bug排查:若选择tcp过滤器，则默认选择"ip and tcp"
	{
		char filter[] = "ip and tcp";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)               //检查已选择的过滤器
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}
	else {
		CString str;
		char *filter;
		int len, x;
		this->m_comboBoxRule.GetLBText(filter_index, str);                   //从所选项中获得过滤器字符串，用作过滤器
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (x = 0; x < len; x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			free(filter);                                                    //释放malloc的空间，并将指针置为空
		    filter = NULL;
			return -1;
		}
	}


	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath, 0, 512);
	memset(filename, 0, 64);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);                                //如果没有就建一个SavedData文件夹用以存储数据
	}

	time_t nowtime;
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y-%m-%d %H-%M-%S", ltime);
	strcpy(filepath, "SavedData\\");
	strcat(filename, thistime);
	strcat(filename, ".pcap");                                                 //用追加的方式以当前时间构造保存的文件名，存入当前文件夹下的SavedData文件夹中

	strcat(filepath, filename);                                                //filepath
	dumpfile = pcap_dump_open(adhandle, filepath);                             //dumpfile绑定下载文件路径名
	if (dumpfile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	pcap_freealldevs(alldev);

	/*接收数据，新建线程处理*/
	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, ProtocolAnalyze_CapThread, this, 0, threadCap);
    //安全设置，堆栈大小，入口函数，函数参数（无类型指针），启动选项（0: 线程建立后立即执行入口函数），输出线程ID

	if (m_ThreadHandle == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(str);
		return -1;
	}
	return 1;
}

/*创建线程*/
DWORD WINAPI ProtocolAnalyze_CapThread(LPVOID lpParameter)        
{
	int res, nItem;
	struct tm *ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									  //数据包头
	const u_char *pkt_data = NULL, *pData = NULL;                 //网络中收到的字节流数据
	u_char *ppkt_data;

	CAnalyzerDlg *pthis = (CAnalyzerDlg*)lpParameter;
	if (NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}
	/*回调函数，当每收到一个数据包时会被winpcap调用*/
	while ((res = pcap_next_ex(pthis->adhandle, &header, &pkt_data)) >= 0)               //从interface或离线记录文件获取一个报文传给pkt_data
		                                                                                 //adhandle已打开的捕捉实例的描述符，header报文头，pkt_data报文内容
	{
		if (res == 0)				                                                     //超时
		{
			continue;
		}
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data, 0, sizeof(struct datapkt));                                         //初始化为全0，准备存储本地化后的数据结构

		if (NULL == data)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			free(data);
			data = NULL;
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)                         //if里的函数是会执行的
		{
			free(data);
			data = NULL;
			continue;
		}
		//将数据包保存到打开的文件中，开始捕获中已绑定的dumpfile文件路径
		if (pthis->dumpfile != NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile, header, pkt_data);
		}

		//DWORD start = GetTickCount();                                                   //计时用，注释部分用于计算并显示流量


		//更新各类数据包计数
		pthis->ProtocolAnalyze_updateNPacket();


		//CString str_num;
		//str_num.Format(_T("%.2f"), pthis->Traffic);
		//pthis->m_editNArp.SetWindowText(str_num);


		//将本地化后的数据装入一个链表中，以便后来使用，header主要用来提供长度		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);

		pthis->m_localDataList.AddTail(data);                   //尾部添加
		pthis->m_netDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度，由此可以算出流量

		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

	
		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"), pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

		/*以下为在对应行中插入列*/

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem, 1, timestr);
		//pthis->m_listCtrl.setitem在listControl中按列插入


		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"), data->len);
		pthis->m_listCtrl.SetItemText(nItem, 2, buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem, 3, buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem, 4, buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (data->iph6 && 0x86dd == data->ethh->type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02X:"), data->iph6->saddr[n]);
				else
					buf.AppendFormat(_T("%02X"), data->iph6->saddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 6, buf);

		/*获得目的IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)                  //ARP协议
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (0x0800 == data->ethh->type) {           //IPv4协议
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {           //IPv6协议
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02X:"), data->iph6->daddr[n]);
				else
					buf.AppendFormat(_T("%02X"), data->iph6->daddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 7, buf);

		/*识别三次握手*/
		buf.Empty();
		if (data ->tcph && 1 == data->tcph->syn && 1 != data -> tcph ->ack)               //第一次握手
		{
			buf = ("第一次握手");
			//free(data);
		}
		if (data -> tcph && 1 == data->tcph->syn && 1 == data -> tcph -> ack) {           //第二次握手
			buf = ("第二次握手");
			//free(data);
		}
		if (data ->tcph && 1 != data->tcph->syn && 1 == data -> tcph -> ack &&  1 == data -> tcph -> psh) {           //第三次握手
			buf = ("第三次握手");
			//free(data);
		}
		pthis->m_listCtrl.SetItemText(nItem, 8, buf);
		buf.Empty();
		/*对包计数*/
		pthis->npkt++;


		pthis->m_PacketsLen += header->len;                                                //接受包的总长度

      /*if (GetTickCount() - m_TickCount > 1000)//每秒读取计算一次。GetTickCount()返回的是毫秒数
		{
			m_Speed = pthis-> m_PacketsLen / 1000.0;//speed .单位kbps
			m_TickCount = GetTickCount();//返回从启动到当前经过的毫秒数
			printf("Packets:%.0f/s Speed:%.3f Kbps\r", m_Packet_Count, m_Speed);
		}*/
		/*float passtime = 0;
		DWORD end = GetTickCount();
	    passtime = end - start;
		pthis->Traffic = ((pthis->m_PacketsLen * 8/1000000)/ (passtime/1000));               //用于计算流量
		//CString str_num;
		str_num.Format(_T("%.2f"), pthis ->Traffic);
		pthis->m_editNArp.SetWindowText(str_num);*/
		//Sleep(5000);
		//free(data);
		//data = NULL;


		free(ppkt_data);
		ppkt_data = NULL;
	}
	return 1;
}

//更新数据包信息
int CAnalyzerDlg::ProtocolAnalyze_updateEdit(int index)
{
	POSITION localpos, netpos;
	localpos = this->m_localDataList.FindIndex(index);                                       //获得由基于零的索引指定的元素位置
	netpos = this->m_netDataList.FindIndex(index);

	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));   //根据位置决定显示的数据包的内容
	u_char * net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

	CString buf;
	print_packet_hex(net_data, local_data->len, &buf);                                       //将数据包以十六进制的方式打印
	

	this->m_edit.SetWindowText(buf);

	return 1;
}

//更新数据统计
int CAnalyzerDlg::ProtocolAnalyze_updateNPacket()
{
	CString str_num;
	str_num.Format(_T("%d"), this->npacket.n_arp);
	this->m_editNArp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_http);
	this->m_editNHttp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_icmp);
	this->m_editNIcmp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_ip6);
	this->m_editNIpv6.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_other);
	this->m_editNOther.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_sum);
	this->m_editNSum.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_tcp);
	this->m_editNTcp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_udp);
	this->m_editNUdp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_ip);
	this->m_editNIpv4.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_dns);
	this->m_editNDns.SetWindowText(str_num);


	return 1;
}

//更新树形控件
int CAnalyzerDlg::ProtocolAnalyze_updateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;

	this->m_treeCtrl.DeleteAllItems();

	localpos = this->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));

	HTREEITEM root = this->m_treeCtrl.GetRootItem();                              //得到根结点
	str.Format(_T("接收到的第%d个数据包"), index + 1);                            //注意要加1
	HTREEITEM data = this->m_treeCtrl.InsertItem(str, root);

	/*处理帧数据*/
	HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("数据链路层数据"), data);        //树形分支-1
	//源MAC
	str.Format(_T("源MAC地址："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02X-"), local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02X"), local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC地址："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02X-"), local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02X"), local_data->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%02x"), local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str, frame);


	/*处理IP、ARP、IPv6数据包*/
	if (0x0806 == local_data->ethh->type)							            //ARP
	{
		HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP协议首部"), data);     //树形分支-2
		str.Format(_T("硬件类型：%d"), local_data->arph->ar_hrd);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), local_data->arph->ar_pro);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), local_data->arph->ar_hln);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), local_data->arph->ar_pln);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), local_data->arph->ar_op);
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方MAC地址："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02X-"), local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02X"), local_data->arph->ar_srcmac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方IP地址："));
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方MAC地址："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02X-"), local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02X"), local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方IP地址："));
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

	}
	else if (0x0800 == local_data->ethh->type) {					                  //IPv4的情况下处理网络层、传输层

		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP协议首部"), data);             //树形分支-2

		str.Format(_T("版本：%d"), local_data->iph->version);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("IP首部长度：%d"), (local_data->iph->ihl) * 4);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), local_data->iph->tos);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), local_data->iph->tlen);
		this->m_treeCtrl.InsertItem(str, ip);
		unsigned char * p = (unsigned char *)(&local_data->iph->id);
		str.Format(_T("标识：0x%02x%02x"), *p ,*(p + 1));
		//str.Format(_T("标识：0x%02x"), local_data->iph->id);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("片偏移：%d"), (local_data->iph->frag_off) * 8);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), local_data->iph->ttl);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("协议：%d"), local_data->iph->proto);
		this->m_treeCtrl.InsertItem(str, ip);
		unsigned char * q = (unsigned char *)(&local_data->iph->check);
		str.Format(_T("首部校验和：0x%02x%02x"), *q,*( q + 1));
		//str.Format(_T("首部校验和：0x%02x"), local_data->iph->check);
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("源IP地址："));
		struct in_addr in;                                                           //WinPcap定义的数据结构
		in.S_un.S_addr = local_data->iph->saddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("目的IP地址："));
		in.S_un.S_addr = local_data->iph->daddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		/*处理传输层ICMP、UDP、TCP*/
		if (1 == local_data->iph->proto)							                 //ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMP协议首部"), data);    //树形分支-3

			str.Format(_T("类型:%d"), local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str, icmp);
			unsigned char * p = (unsigned char *)(&local_data->icmph->chksum);
			str.Format(_T("校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("校验和:%d"), local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str, icmp);

		}
		else if (6 == local_data->iph->proto) {				                          //TCP

			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议首部"), data);

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  首部长度:%d"), (local_data->tcph->doff) * 4);
			this->m_treeCtrl.InsertItem(str, tcp);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +标志位"), tcp);

			str.Format(_T("CWR %d"), local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ECE %d"), local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("URG %d"), local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ACK %d"), local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("PSH %d"), local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("RST %d"), local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("SYN %d"), local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("FIN %d"), local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			unsigned char * p = (unsigned char *)(&local_data->tcph->check);
			str.Format(_T("  校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (17 == local_data->iph->proto) {				                         //UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议首部"), data);          //树形分支-3

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			unsigned char * p = (unsigned char *)(&local_data->udph->check);
			str.Format(_T("校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}
	else if (0x86dd == local_data->ethh->type) {		                                  //IPv6的情况下处理网络层、传输层
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6协议首部"), data);              //树形分支-2

		
		str.Format(_T("版本:%d"), local_data->iph6->flowtype);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("流类型:%d"), local_data->iph6->version);
		this->m_treeCtrl.InsertItem(str, ip6);
		
		str.Format(_T("流标签:%d"), local_data->iph6->flowid);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), local_data->iph6->plen);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), local_data->iph6->nh);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("跳限制:%d"), local_data->iph6->hlim);
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		int n;
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		/*处理传输层ICMPv6、UDP、TCP*/
		if (0x3a == local_data->iph6->nh)							                          //ICMPv6
		{
			HTREEITEM icmp6 = this->m_treeCtrl.InsertItem(_T("ICMPv6协议首部"), data);          //树形分支-3

			str.Format(_T("类型:%d"), local_data->icmph6->type);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), local_data->icmph6->code);
			this->m_treeCtrl.InsertItem(str, icmp6);
			unsigned char * p = (unsigned char *)(&local_data->icmph6->chksum);
			str.Format(_T("校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("校验和:%d"), local_data->icmph6->chksum);
			this->m_treeCtrl.InsertItem(str, icmp6);

		}
		else if (0x06 == local_data->iph6->nh) {				                         //TCP

			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议首部"), data);          //树形分支-3

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  首部长度:%d"), (local_data->tcph->doff) * 4);
			this->m_treeCtrl.InsertItem(str, tcp);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("+标志位"), tcp);              //树形分支-4

			str.Format(_T("CWR %d"), local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ECE %d"), local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("URG %d"), local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ACK %d"), local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("PSH %d"), local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("RST %d"), local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("SYN %d"), local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("FIN %d"), local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			unsigned char * p = (unsigned char *)(&local_data->tcph->check);
			str.Format(_T("  校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (0x11 == local_data->iph6->nh) {				                       //UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议首部"), data);      //树形分支-3

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			unsigned char * p = (unsigned char *)(&local_data->udph->check);
			str.Format(_T("校验和：0x%02x%02x"), *p, *(p + 1));
			//str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}

	return 1;
}

/*保存文件*/
int CAnalyzerDlg::ProtocolAnalyze_saveFile()
{
	CFileFind find;
	if (NULL == find.FindFile(CString(filepath)))         //查找一个目录中的指定文件
	{
		MessageBox(_T("保存文件遇到未知意外"));
		return -1;
	}

	//打开文件对话框
	CFileDialog   FileDlg(FALSE, _T("pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,_T("常用数据包格式文件(*.pcap)|*.pcap|"), NULL);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	FileDlg.m_ofn.lpstrTitle = _T("保存文件");
	if (FileDlg.DoModal() == IDOK)
	{
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);    //把dump到SavedData文件夹中的数据包copy到选定的位置
	}
	return 1;
}


/*读取文件*/
int CAnalyzerDlg::ProtocolAnalyze_readFile(CString path)           
{
	int res, nItem, i;
	struct tm *ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									     //数据包头
	const u_char *pkt_data = NULL;                                   //网络中收到的字节流数据
	u_char *ppkt_data;

	//CAnalyzerDlg *pthis = this;						             //一些代码改造自ProtocolAnalyze_CapThread，为节约工作量，故保留pthis指针
	pcap_t *fp;

	//首先处理一下路径，利用pcap_open_offline打开文件时，
	//路径需要用char *类型，不能用CString强制转换后的char *
	int len = path.GetLength() + 1;							         //注意这一个细节，必须要加1，否则会出错
	char* charpath = (char *)malloc(len);
	memset(charpath, 0, len);
	if (NULL == charpath)
	{
		//free(charpath);
		return -1;
	}

	for (i = 0; i < len; i++)
		charpath[i] = (char)path.GetAt(i);

	//打开相关文件
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
	{
		MessageBox(_T("打开文件错误") + CString(errbuf));
		//free(charpath);
		return -1;
	}
	//free(charpath);
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data, 0, sizeof(struct datapkt));

		if (NULL == data)
		{
			MessageBox(_T("空间已满，无法接收新的数据包"));
			//free(data);
			return  -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyze_frame(pkt_data, data, &(this->npacket)) < 0)
		{
			//free(data);
			continue;
		}
		//更新各类数据包计数
		this->ProtocolAnalyze_updateNPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);

		this->m_localDataList.AddTail(data);                   //在链表尾部添加元素
		this->m_netDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);                       //时间转换
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"), this->npkt);
		nItem = this->m_listCtrl.InsertItem(this->npkt, buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		this->m_listCtrl.SetItemText(nItem, 1, timestr);

		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"), data->len);
		this->m_listCtrl.SetItemText(nItem, 2, buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		this->m_listCtrl.SetItemText(nItem, 3, buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		this->m_listCtrl.SetItemText(nItem, 4, buf);

		/*获得协议*/
		this->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else  if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)
					buf.AppendFormat(_T("%02X-"), data->iph6->saddr[i]);
				else
					buf.AppendFormat(_T("%02X"), data->iph6->saddr[i]);
			}
		}
		this->m_listCtrl.SetItemText(nItem, 6, buf);

		/*获得目的IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)

					buf.AppendFormat(_T("%02X-"), data->iph6->daddr[i]);
				else
					buf.AppendFormat(_T("%02X"), data->iph6->daddr[i]);
			}
		}
		this->m_listCtrl.SetItemText(nItem, 7, buf);

		/*识别三次握手*/
		buf.Empty();
		if (data->tcph && 1 == data->tcph->syn && 1 != data->tcph->ack)                                     //第一次握手
		{
			buf = ("第一次握手");
		}
		if (data->tcph && 1 == data->tcph->syn && 1 == data->tcph->ack) {                                   //第二次握手
			buf = ("第二次握手");
		}
		if (data->tcph && 1 != data->tcph->syn && 1 == data->tcph->ack && 1 == data->tcph->psh) {           //第三次握手
			buf = ("第三次握手");
		}
		this->m_listCtrl.SetItemText(nItem, 8, buf);

		/*对包计数*/
		this->npkt++;

		//free(data);
		//free(ppkt_data);
	}

	pcap_close(fp);

	return 1;
}


/*实现点击列头的排序功能*/

//比较函数
static int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lparam2, LPARAM lparamSort)
{
	CListCtrl *pListCtrl = (CListCtrl *)lparamSort;             //这里都是固定语法，适当了解
	LVFINDINFO findInfo;
	findInfo.flags = LVFI_PARAM;
	findInfo.lParam = lParam1;
	int iItem1 = pListCtrl->FindItem(&findInfo, -1);
	findInfo.lParam = lparam2;
	int iItem2 = pListCtrl->FindItem(&findInfo, -1);            //这里都是固定语法，适当了解

	CString strItem1 = pListCtrl->GetItemText(iItem1, dwSelColID);
	CString strItem2 = pListCtrl->GetItemText(iItem2, dwSelColID);
	char * str1 = (char *)strItem1.GetBuffer(strItem1.GetLength());
	char * str2 = (char *)strItem2.GetBuffer(strItem1.GetLength());


	if (bASC)
		return strcmp(str1, str2);
	else
		return strcmp(str2, str1);
}


//列表头点击事件
void CAnalyzerDlg::OnColumnclickList1(NMHDR *pNMHDR, LRESULT *pResult)       
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	if (dwSelColID != pNMLV->iSubItem)
	{
		dwSelColID = pNMLV->iSubItem;
		bASC = bASC;
	}
	else
		bASC = !bASC;
	int count = m_listCtrl.GetItemCount();
	for (int i = 0; i < count; i++)
		m_listCtrl.SetItemData(i,i);
	m_listCtrl.SortItems(CompareFunc, (LPARAM)(&m_listCtrl));
	//OnNMCustomdrawList1(pNMHDR,pResult);
	*pResult = 0;
}
