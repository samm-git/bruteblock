<?xml version="1.0" encoding="windows-1251"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>BruteBlock V@RELEASE@</title>
</head>
<body>
<a href="index.html.en">English Version</a>
<h1 style="text-align:center">BRUTEBLOCK V@RELEASE@</h1>

<h2>� ��������� bruteblock</h2> 

��������� bruteblock ��������� ����������� �������
������� ������� � �������� UNIX. ��������� ����������� ������ ���������� ����� �
������� ip ��������������� � ������� firewall ipfw2. ����� ���������,
����������� �������������, ����� ��������� ������� �� �� ���� �������.
������������� ���������� ��������� ��������� ������������ ������� ���
����������� ����� ������. ������� �������� �� C � �� ���������� ������ �������
��������, ������� � ��������� IPFW2 ����� RAW SOCKETS API.

<h2>��������� ����������</h2>
������� ������� ��� ������ OS <a href="http://www.freebsd.org" target="_blank">FreeBSD</a> 5.3 ��� ���� (����������� �� FreeBSD 5.3,
5.4, 6.1), firewall IPFW. ��� ���������� � ������ ��������� ���������
���������� ���������� ���������
<a href="http://www.pcre.org" target="_blank">PCRE</a>, ��������� � ������ 
������ ��� <a href="http://www.freshports.org/devel/pcre/" target="_blank">devel/pcre</a>.

<h2>������� ������</h2>
������� bruteblock ������� �� ���� ������ � bruteblock � bruteblockd. ����
bruteblock ������������� � <tt>/etc/syslog.conf</tt> � ������������ ������ ������� �
���������� ip ������� � ������� IPFW2. ������ ������ IPFW2 �������� ����� ����:
�����/�����, ��������. �������� � ��� �������������� ����, ������� �����
��������� ����� ����� ������� unsigned int. ��� ����� �������������� ��� �������
������������ ������� � �������� IPFW2. ������� bruteblock ���������� ��� ����
��� �������� ������� �������� �������, � unix �������. ������� bruteblockd
������������ ��������� ��������� ������� � ������� ���������� ������. �����
������� ������� �������� ������������� IPC bruteblock/bruteblockd � ����������
����������� ������� � ����� ������� ������ ��� ���������� ��������. ����� ����,
������ ����� ����� �������� ������ ���������� ���������� � ��� �������������
��������������� ���.

<h2>������� �������</h2>
<a href="bruteblock-@RELEASE@.tar.gz">bruteblock-@RELEASE@.tar.gz</a> - �������� ��� �������.<br/>
<a href="CHANGES">CHANGES</a> - ������� ���������.


<h2>���������</h2>
��� ���������� ��������� ������ ��������� make � ����������
bruteblock. ���������� ����������� ����� bruteblock � bruteblockd � �������,
��������, � ������� <tt>/usr/local/bin</tt>. ���������� ���� bruteblock-ssh.conf �
���������� � ����������������� �������, �������� �
<tt>/usr/local/etc/bruteblock-ssh.conf</tt> � �������������� ���. ������� ���������
bruteblock � ���������������� ���� syslogd - <tt>/etc/syslog.conf</tt>:
<pre>
auth.info;authpriv.info      |exec /usr/local/bin/bruteblock -f /usr/local/etc/bruteblock/ssh.conf 
</pre>
� ������������� syslogd, ��������, �������� /etc/rc.d/syslogd restart. ���������
����� bruteblockd ������ ��� �� ����� ������� ��� � � ����� ������������
bruteblock, �������� '<tt># /usr/local/bin/bruteblockd -t 1</tt>'. ������� �������
ipfw2, ����������� ����������� ��� ������� �� ��������� �������, ��������:
<pre>
${fwcmd} add deny ip from me to table\(1\)
${fwcmd} add deny ip from table\(1\) to me
</pre>
� ������������� ������������ firewall (<tt>/etc/rc.d/ipfw restart</tt>). ���� �� ��
������� ��������� � bruteblock ����� ����������� ������� ������� ������� SSH
�������.

<h2>������������</h2>
���������������� ���� ������� bruteblock �������� ����� ����:<br/> 
<tt>regexp</tt> - ���������� ���������, �� �������� ������������ ����� ip ������� ���
�������� ������� �������. ������ ���������� ��������� - PCRE.<br/>
<tt>"regexp0","regexp1",... "regexp9"</tt> - ������������ ���� ���������� �� 10
�������������� ���������� ���������.
�������� ������� �������. ������ ���������� ��������� - PCRE.<br/>
<tt>max_count</tt> � ���������� ��������� ������� ����� � ������� �������  
<tt>within_time</tt>, ����� ������� bruteblock ��������� ip � ������� ipfw2.<br/>
<tt>within_time</tt> � �����, � �������� � ������� �������� ������ ��������� <tt>max_count</tt>
��������� ������� �����.<br/> 
<tt>reset_ip</tt> � ����� ����� ������� ����������, �� ��������� �������� bruteblockd
������� ������� �� �������.<br/>
<tt>ipfw2_table_no</tt> � ����� ������� ipfw2. ������ ��������� � ���������� -t
bruteblockd � ������� ������� � ������� ipfw2.

<h2>����� �� ��������</h2>
�������� ������� ������������ ��� ������ ���������� ��������, �������� 
��������� IPv6 (��������� ������), �������������� ��������� ������ bruteblock, 
������� ���� security/bruteblock, �������� ��������� pf. 
<br/><br/>

<i>� ���� ��� ������� � ������ ���������, ���������� � ����������. � ������
������������� ������� � ������ �� samm [at] os2.kiev.ua.</i>

<hr/>
<small>&copy; Alex Samorukov</small>

<p>
<a href="http://validator.w3.org/check?uri=referer"><img
 src="http://www.w3.org/Icons/valid-xhtml10"
alt="Valid XHTML 1.0 Transitional" border="0" height="31" width="88" /></a>
<a href="http://freshmeat.net/"><img
 src="http://images.freshmeat.net/img/link_button_2.gif" width="88" height="31"
 border="0" alt="freshmeat.net"/></a>
</p>
</body>
</html>
