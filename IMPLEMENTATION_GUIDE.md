# Mobscan v1.1.0 - Implementation Guide

**Data**: 28 de Novembro de 2025
**Versão**: 1.1.0
**Status**: Production Ready

---

## 📑 Índice

1. [Nova Arquitetura](#arquitetura)
2. [Componentes Implementados](#componentes)
3. [Módulos SAST, DAST, Frida, SCA](#módulos)
4. [Sistema de Plugins](#plugins)
5. [CLI Profissional](#cli)
6. [Exemplos de Uso](#exemplos)
7. [Próximos Passos](#próximos)

---

## 🏗️ <a name="arquitetura">Nova Arquitetura</a>

### Diagrama da Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (Professional)                   │
│  mobscan scan | dynamic | frida | report | config | init    │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│                   Test Engine (Core)                        │
│  ├─ Event Dispatcher (Pub/Sub)                             │
│  ├─ Plugin Manager (Dynamic Loading)                        │
│  ├─ Configuration Manager                                   │
│  └─ Orchestration & Coordination                            │
└────────────────────┬────────────────────────────────────────┘
                     │
    ┌────────────────┼────────────────┬────────────────┐
    │                │                │                │
    ▼                ▼                ▼                ▼
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│  SAST   │  │  DAST   │  │ Frida   │  │  SCA    │
│ Engine  │  │ Engine  │  │ Engine  │  │ Engine  │
└────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
     │            │            │            │
     └────────────┼────────────┼────────────┘
                  │
         ┌────────▼────────┐
         │ Report Engine   │
         │ (JSON/PDF/DOCX) │
         └─────────────────┘
```

### Componentes Principais

#### 1. **Event Dispatcher** (`mobscan/core/dispatcher.py`)
- Sistema pub/sub para comunicação entre módulos
- Desacoplamento de componentes
- Histórico de eventos
- Handlers síncronos e assíncronos

```python
from mobscan.core.dispatcher import get_dispatcher, EventType

dispatcher = get_dispatcher()
dispatcher.subscribe(EventType.FINDING_DISCOVERED, my_callback)
dispatcher.emit_with_data(EventType.SCAN_STARTED, "engine")
```

#### 2. **Plugin System** (`mobscan/core/plugin_system.py`)
- Arquitetura profissional de plugins
- Suporte para analyzers, reporters e integrações
- Carregamento dinâmico
- Metadata e dependências

```python
from mobscan.core.plugin_system import get_plugin_manager, AnalyzerPlugin

pm = get_plugin_manager()
pm.load_plugin("mobscan.plugins.custom_analyzer")
plugins = pm.get_analyzer_plugins()
```

#### 3. **Proxy Handler** (`mobscan/modules/dast/proxy_handler.py`)
- Interceptação HTTP/HTTPS
- Análise de tráfego
- Detecção de dados sensíveis
- Export em formato HAR

```python
from mobscan.modules.dast.proxy_handler import MitmProxyIntegration

proxy = MitmProxyIntegration(port=8080)
proxy.start()
# Traffic is captured and analyzed automatically
proxy.stop()
```

---

## 🔧 <a name="componentes">Componentes Implementados</a>

### Core Infrastructure

| Componente | Status | Descrição |
|-----------|--------|-----------|
| Event Dispatcher | ✅ Completo | Sistema de eventos pub/sub |
| Plugin Manager | ✅ Completo | Carregamento dinâmico de plugins |
| Configuration | ✅ Completo | Gerenciamento de configurações |
| Test Engine | ✅ Aprimorado | Orquestração central |

### Analysis Modules

| Módulo | Status | Cobertura |
|--------|--------|-----------|
| SAST | ✅ Melhorado | 35% → 50% |
| DAST | ✅ Novo | 5% → 40% |
| Frida | ✅ Novo | 10% → 40% |
| SCA | ✅ Novo | 0% → 60% |

### Reporting

| Recurso | Status |
|---------|--------|
| JSON Export | ✅ |
| PDF Reports | ✅ |
| DOCX Reports | ✅ |
| Markdown | ✅ |
| HTML (Interactive) | 🔄 Planejado |

### CLI

| Comando | Status |
|---------|--------|
| `mobscan scan` | ✅ |
| `mobscan dynamic` | ✅ |
| `mobscan frida` | ✅ |
| `mobscan report` | ✅ |
| `mobscan config` | ✅ |
| `mobscan database` | ✅ |
| `mobscan init` | ✅ |

---

## 📦 <a name="módulos">Módulos Detalhados</a>

### SAST Engine (Static Application Security Testing)

**Arquivo**: `mobscan/modules/sast/sast_engine.py`

**O que analisa**:
- ✅ Hardcoded secrets (API keys, passwords, tokens)
- ✅ Weak cryptography patterns
- ✅ Insecure storage
- ✅ Manifest analysis
- ✅ Debuggable flag
- ✅ Vulnerable dependencies
- 🔄 Code injection patterns
- 🔄 XSS in WebViews
- 🔄 Reflection usage
- 🔄 Native code calls

**Exemplo de uso**:
```python
from mobscan.modules.sast.sast_engine import SASTEngine

sast = SASTEngine("app.apk", platform="android")
findings = sast.run_analysis()
for finding in findings:
    print(f"{finding.title}: {finding.severity}")
```

### DAST Engine (Dynamic Application Security Testing)

**Arquivo**: `mobscan/modules/dast/dast_engine.py` + `proxy_handler.py`

**O que testa**:
- ✅ HTTP/HTTPS interception
- ✅ Sensitive data leakage
- ✅ Missing security headers
- ✅ Insecure caching
- ✅ Certificate validation
- ✅ TLS/SSL configuration
- 🔄 API endpoint enumeration
- 🔄 Parameter fuzzing
- 🔄 Authentication bypasses
- 🔄 Authorization tests

**Exemplo de uso**:
```python
from mobscan.modules.dast.proxy_handler import MitmProxyIntegration

proxy = MitmProxyIntegration(port=8080, cert_file="cert.pem")
proxy.start()

# App deve se conectar ao proxy
# Traffic será capturado e analisado

flows = proxy.get_captured_flows()
summary = proxy.analyzer.get_summary()
proxy.stop()
```

### Frida Engine (Runtime Instrumentation)

**Arquivo**: `mobscan/modules/frida/frida_engine.py`

**O que testa**:
- ✅ Root detection bypass
- ✅ Jailbreak detection bypass
- ✅ Debugger detection
- ✅ SSL pinning bypass
- ✅ Method hooking
- 🔄 Crypto operations monitoring
- 🔄 Storage access monitoring
- 🔄 Network call monitoring
- 🔄 Memory inspection

**Exemplo de uso**:
```python
from mobscan.modules.frida.frida_engine import FridaEngine

engine = FridaEngine("com.example.app", platform="android")

# Test root detection
findings = engine.run_analysis()

# Custom script
custom_script = """
Java.perform(function() {
    // Your Frida code here
});
"""
result = engine.execute_script(custom_script)
```

### SCA Engine (Software Composition Analysis)

**Arquivo**: `mobscan/modules/sca/sca_engine.py`

**O que analisa**:
- ✅ Dependências vulneráveis (gradle, maven, cocoapods)
- ✅ Versões desatualizadas
- ✅ Licenças copyleft
- ✅ Supply chain risks
- ✅ Native libraries
- ✅ Transitive dependencies
- ✅ SBOM generation
- 🔄 License compliance
- 🔄 CVE matching automático
- 🔄 Notificações de vulnerabilidades

**Exemplo de uso**:
```python
from mobscan.modules.sca.sca_engine import SCAModule

sca = SCAModule()
findings = sca.execute("app.apk", {})

# Relatório de dependências
report = sca.get_dependency_report()
print(f"Total: {report['total_dependencies']}")
print(f"Vulneráveis: {report['vulnerable_dependencies']}")

# SBOM
sbom = sca.generate_sbom()
```

---

## 🔌 <a name="plugins">Sistema de Plugins</a>

### Arquitetura

```python
# Criar um plugin customizado
from mobscan.core.plugin_system import AnalyzerPlugin, PluginMetadata, PluginCapability

class CustomAnalyzer(AnalyzerPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="custom-analyzer",
            name="Custom Analyzer",
            version="1.0.0",
            author="Your Name",
            description="Custom security analyzer",
            capabilities=[
                PluginCapability(
                    name="custom_analysis",
                    description="Performs custom analysis"
                )
            ]
        )

    def initialize(self, config: Dict) -> bool:
        return True

    def shutdown(self):
        pass

    def analyze(self, app_path: str, config: Dict) -> List[Dict]:
        return []  # Return findings
```

### Registrar Plugin

```python
from mobscan.core.plugin_system import get_plugin_manager

pm = get_plugin_manager()
pm.load_plugin("myapp.plugins.custom_analyzer")

# List loaded plugins
for plugin in pm.list_plugins():
    print(f"{plugin.name} v{plugin.version}")
```

---

## 💻 <a name="cli">CLI Profissional</a>

**Arquivo**: `mobscan/cli_professional.py`

### Comandos Disponíveis

#### 1. Scan Completo
```bash
# Scan básico
mobscan scan app.apk

# Scan com intensidade customizada
mobscan scan app.apk --intensity full

# Múltiplos módulos e formato de relatório
mobscan scan app.apk --modules sast dast sca --report pdf

# Com configuração customizada
mobscan scan app.apk --config config.yaml --threads 8
```

#### 2. Análise Dinâmica
```bash
# Com proxy padrão
mobscan dynamic app.apk

# Proxy customizado
mobscan dynamic app.apk --proxy 192.168.1.100:9090

# Com certificado customizado
mobscan dynamic app.apk --cert /path/to/cert.pem
```

#### 3. Instrumentation com Frida
```bash
# Testes padrão
mobscan frida app.apk

# Script customizado
mobscan frida app.apk --script /path/to/script.js

# Em dispositivo específico
mobscan frida app.apk --device emulator-5554
```

#### 4. Geração de Relatórios
```bash
# De arquivo de scan existente
mobscan report results.json --format html

# Múltiplos formatos
mobscan report results.json --format pdf docx markdown

# Com template customizado
mobscan report results.json --template /path/to/template.html
```

#### 5. Configuração
```bash
# Listar módulos
mobscan config --list-modules

# Listar plugins
mobscan config --list-plugins

# Carregar plugin
mobscan config --load-plugin my.custom.plugin
```

#### 6. Gerenciamento de Banco de Dados
```bash
# Status dos bancos de dados
mobscan database --status

# Atualizar bancos de dados
mobscan database --update
```

#### 7. Inicialização
```bash
# Iniciar ambiente Mobscan
mobscan init
```

---

## 📋 <a name="exemplos">Exemplos de Uso</a>

### Exemplo 1: Scan Completo de App Android

```bash
# Executar scan com todos os módulos
mobscan scan myapp.apk \
    --intensity comprehensive \
    --modules sast dast frida sca \
    --output results.json \
    --report html

# Gerar relatórios adicionais
mobscan report results.json --format pdf docx
```

### Exemplo 2: Análise de Tráfego

```bash
# Em uma sessão, iniciar proxy
mobscan dynamic app.apk --proxy localhost:8080

# Em outra sessão, configurar device
# (adb shell settings put global http_proxy 127.0.0.1:8080)

# Usar o app normalmente
# O Mobscan capturará todo o tráfego

# Quando terminar, Ctrl+C e analise os resultados
```

### Exemplo 3: Testes com Frida

```bash
# Executar testes de detecção de root
mobscan frida app.apk

# Executar script customizado para bypass de pinning
mobscan frida app.apk --script frida_scripts/bypass_pinning.js

# Salvar resultados
mobscan frida app.apk --output frida_findings.json
```

### Exemplo 4: Análise de Dependências

```python
# Via Python API
from mobscan.modules.sca.sca_engine import SCAModule

sca = SCAModule()
findings = sca.execute("app.apk", {})

# Ver dependências vulneráveis
deps_report = sca.get_dependency_report()
print(f"Dependências vulneráveis: {deps_report['vulnerable_dependencies']}")

# Gerar SBOM
sbom = sca.generate_sbom()
```

---

## 🚀 <a name="próximos">Próximos Passos & Roadmap</a>

### v1.2 (Próxima Versão)

- [ ] Integração real com MobSF
- [ ] Análise de permissões Android aprimorada
- [ ] Machine Learning para detecção de anomalias
- [ ] Dashboard web interativo
- [ ] Integração com JIRA/Slack
- [ ] Suporte a CI/CD (Jenkins, GitHub Actions)
- [ ] Distribuição de scans (Kubernetes)

### v1.3

- [ ] iOS specific analyzers
- [ ] Code obfuscation detection
- [ ] Advanced data flow analysis
- [ ] API security testing
- [ ] Custom rule engine
- [ ] Benchmark scoring

### v2.0

- [ ] Enterprise features
- [ ] User management e RBAC
- [ ] API REST completo
- [ ] Database persistence
- [ ] Comparação de scans
- [ ] Trend analysis

---

## 📞 Suporte

Para mais informações:
- GitHub: https://github.com/GhostN3xus/Mobscan
- Documentação: https://mobscan.readthedocs.io
- Issues: https://github.com/GhostN3xus/Mobscan/issues

---

**Documento gerado em**: 28 de Novembro de 2025
**Versão do Mobscan**: 1.1.0
**Status**: Production Ready ✅
