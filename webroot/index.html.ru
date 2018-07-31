<?xml version="1.0" encoding="windows-1251"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>BruteBlock V@RELEASE@</title>
</head>
<body>
<a href="index.html.en">English Version</a>
<h1 style="text-align:center">BRUTEBLOCK V@RELEASE@</h1>

<h2>О программе bruteblock</h2> 

Программа bruteblock позволяет блокировать попытки
подбора паролей к сервисам UNIX. Программа анализирует журнал запущенных служб и
заносит ip злоумышленников в таблицу firewall ipfw2. Через некоторое,
определённое пользователем, время программа удаляет их из этой таблицы.
Использование регулярных выражений позволяет использовать утилиту для
практически любой службы. Утилита написана на C и не использует вызова внешних
программ, работая с таблицами IPFW2 через RAW SOCKETS API.

<h2>Системные требования</h2>
Утилита требует для работы OS <a href="http://www.freebsd.org" target="_blank">FreeBSD</a> 5.3 или выше (проверялась на FreeBSD 5.3,
5.4, 6.1), firewall IPFW. Для компиляции и работы программы требуется
библиотека регулярных выражений
<a href="http://www.pcre.org" target="_blank">PCRE</a>, доступная в дереве 
портов как <a href="http://www.freshports.org/devel/pcre/" target="_blank">devel/pcre</a>.

<h2>Принцип работы</h2>
Утилита bruteblock состоит из двух частей – bruteblock и bruteblockd. Файл
bruteblock прописывается в <tt>/etc/syslog.conf</tt> и обеспечивает анализ журнала и
добавление ip адресов в таблицу IPFW2. Каждая запись IPFW2 содержит такие поля:
адрес/маска, значение. Значение – это необязательное поле, которое может
содержать любое число формата unsigned int. Оно может использоваться для выборки
подмножества таблицы в правилах IPFW2. Утилита bruteblock использует это поле
для хранения времени действия правила, в unix формате. Утилита bruteblockd
периодически проверяет указанную таблицу и удаляет устаревшие записи. Таким
образом удалось избежать необходимости IPC bruteblock/bruteblockd и обеспечить
возможность хранить в одной таблице записи для нескольких сервисов. Кроме того,
всегда можно легко получить список актуальных блокировок и при необходимости
отредактировать его.

<h2>Скачать утилиту</h2>
<a href="bruteblock-@RELEASE@.tar.gz">bruteblock-@RELEASE@.tar.gz</a> - исходный код утилиты.<br/>
<a href="CHANGES">CHANGES</a> - история изменений.


<h2>Установка</h2>
Для компиляции программы просто запустите make в директории
bruteblock. Скопируйте исполняемые файлы bruteblock и bruteblockd в систему,
например, в каталог <tt>/usr/local/bin</tt>. Скопируйте файл bruteblock-ssh.conf в
директорию с конфигурационными файлами, например в
<tt>/usr/local/etc/bruteblock-ssh.conf</tt> и отредактируйте его. Добавте программу
bruteblock в конфигурационный файл syslogd - <tt>/etc/syslog.conf</tt>:
<pre>
auth.info;authpriv.info      |exec /usr/local/bin/bruteblock -f /usr/local/etc/bruteblock/ssh.conf 
</pre>
и перезапустите syslogd, например, командой /etc/rc.d/syslogd restart. Запустите
демон bruteblockd указав тот же номер таблицы что и в файле конфигурации
bruteblock, например '<tt># /usr/local/bin/bruteblockd -t 1</tt>'. Добавте правила
ipfw2, блокирующие подключения для адресов из выбранной таблицы, например:
<pre>
${fwcmd} add deny ip from me to table\(1\)
${fwcmd} add deny ip from table\(1\) to me
</pre>
и перезагрузите конфигурацию firewall (<tt>/etc/rc.d/ipfw restart</tt>). Если вы всё
сделали правильно – bruteblock будет блокировать попытки подбора паролей SSH
сервера.

<h2>Конфигурация</h2>
Конфигурационный файл утилиты bruteblock содержит такие поля:<br/> 
<tt>regexp</tt> - регулярное выражение, по которому производится поиск ip адресов при
попытках подбора паролей. Формат регулярных выражений - PCRE.<br/>
<tt>"regexp0","regexp1",... "regexp9"</tt> - опциональные поля содержащие до 10
дополнительных регулярных выражений.
попытках подбора паролей. Формат регулярных выражений - PCRE.<br/>
<tt>max_count</tt> – количество неудачных попыток входа в течении времени  
<tt>within_time</tt>, после которых bruteblock добавляет ip в таблицу ipfw2.<br/>
<tt>within_time</tt> – время, в секундах в течении которого должны произойти <tt>max_count</tt>
неудачных попыток входа.<br/> 
<tt>reset_ip</tt> – время жизни правила блокировки, по истечению которого bruteblockd
удаляет правило из таблицы.<br/>
<tt>ipfw2_table_no</tt> – номер таблицы ipfw2. Должен совпадать с параметром -t
bruteblockd и номером таблицы в правиле ipfw2.

<h2>Планы по развитию</h2>
Добавить примеры конфигураций для других популярных сервисов, добавить 
поддержку IPv6 (требуется помощь), оптимизировать алгоритмы работы bruteblock, 
создать порт security/bruteblock, добавить поддержку pf. 
<br/><br/>

<i>Я буду рад отзывам о работе программы, пожеланиям и замечаниям. В случае
возникновения таковых – пишите на samm [at] os2.kiev.ua.</i>

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
