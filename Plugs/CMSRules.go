package Plugs

type RuleData struct {
	Name  string
	value string
	class string
	Type  string
	Rule  string
}
type Mh3Data struct {
	Name  string
	value string
	class string
	mmh3  string
}

// RuleDatas 通过响应头、响应体、图标hash 匹配指纹

var RuleDatas = []RuleData{
	// 中间件
	{"Vulfocus", "vulfocus", "中间件", "code", "(<title>vulfocus)"},
	{"Shiro", "shiro", "中间件", "headers", "(=deleteMe|rememberMe=)"},
	{"Weblogic", "weblogic", "中间件", "code", "(/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png|Welcome to Weblogic Application Server|<i>Hypertext Transfer Protocol -- HTTP/1.1</i>)"},
	{"Weblogic", "weblogic", "中间件", "headers", "(WebLogic)"},
	{"Jboss", "jboss", "中间件", "code", "(Welcome to JBoss|jboss.css)"},
	{"Jboss", "jboss", "中间件", "headers", "(JBoss)"},
	{"Tomcat默认页面", "tomcat", "中间件", "code", "(/manager/html|/manager/status)"},
	{"Struts2", "s2", "中间件", "code", "(org.apache.struts2|Struts Problem Report|struts.devMode|struts-tags|There is no Action mapped for namespace)"},

	//协同办公
	
}

var Mh3Datas = []Mh3Data{
	//{"Tomcat", "dahua", "中间件", "-297069493"},
	{"Spring", "spring", "开发框架", "116323821"},
	{"ThinkPHP", "thinkphp", "开发框架", "1165838194"},
}
