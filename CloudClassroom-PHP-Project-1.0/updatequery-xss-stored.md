# Advisory de Segurança — Stored XSS em updatequery.php

> **Identificador:** CVE pendente de atribuição / ID interno **CC-2026-09**
> **Data de publicação:** 02/08/2026
> **Última atualização:** 02/08/2026
> **Severidade:** Médio
> **CVSS:** 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Cross-site Scripting
> **Status:** Sem correção (unpatched)

---

## 1. Resumo executivo

Foi identificada uma vulnerabilidade em **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), no componente **updatequery.php**, que permite que **um atacante (Nenhuma para injetar (via item 00); interação do usuário: Requerida (vítima abre a página que renderiza o dado))** explore uma falha de **Stored / Persistent Cross-Site Scripting**.

Os campos `queryx`, `ansx` são persistidos sem sanitização e reexibidos dentro de `<textarea>` sem HTML-encoding. Query/Ans são TEXT (sem limite prático → `<script>` completo).

A exploração bem-sucedida pode resultar em **Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa.**

A divulgação segue política responsável/coordenada; a notificação formal ao fornecedor está prevista no pacote de divulgação (ver seções 13 e 14). Até o momento não há correção publicada.

---

## 2. Produtos afetados

| Produto / Componente | Versões afetadas | Versão corrigida | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (e anteriores) | Nenhuma | Afetado |
| Componente: updatequery.php | 1.0 | Nenhuma | Afetado |

- **Repositório / ecossistema:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Stack avaliada:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Produtos não afetados

- Nenhuma outra versão/produto avaliado neste advisory.

---

## 3. Descrição da vulnerabilidade

A vulnerabilidade ocorre devido a **Stored / Persistent Cross-Site Scripting** no componente **updatequery.php**.

Os campos `queryx`, `ansx` são persistidos sem sanitização e reexibidos dentro de `<textarea>` sem HTML-encoding. Query/Ans são TEXT (sem limite prático → `<script>` completo).

**Causa-raiz (trecho do código-fonte):**

**`updatequery.php`**

```php
<textarea name="queryx">...<?php echo $row[...]; ?></textarea>
```

### Condições necessárias

- Autenticação: Nenhuma para injetar (via item 00)
- Interação do usuário: Requerida (vítima abre a página que renderiza o dado)
- Vetor de acesso: Remoto (rede) — método POST
- Pré-condições: Nenhuma para injetar (item 00). Vítima autenticada (admin/faculty) precisa visualizar o registro.

---

## 4. Impacto

A exploração pode permitir:

- Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa

### Impacto sobre a confidencialidade

Baixo — exposição parcial/limitada de informações.

### Impacto sobre a integridade

Baixo — alteração limitada de dados/estado.

### Impacto sobre a disponibilidade

Nenhum — sem impacto direto de disponibilidade.

---

## 5. Classificação

### CVSS

- **Pontuação:** 6.1
- **Severidade:** Médio
- **Vetor:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

| Métrica | Valor |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Changed (C) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

### CWE

- CWE-79: Cross-site Scripting

### CAPEC

- **CAPEC-63 – Cross-Site Scripting (XSS)**

---

## 6. Cenário de exploração

Um possível cenário de exploração ocorre da seguinte forma:

1. Enviar POST para `updatequery.php` gravando o payload de breakout no campo `queryx`.
2. Payload: `</textarea><script>alert(document.domain)</script>` (fecha o textarea).
3. Abrir novamente a página; o payload é refletido SEM encoding e executa.
4. Encadear com o cookie sem HttpOnly (item 24) para roubo de sessão do admin.

---

## 7. Evidências técnicas

### Componente afetado

```text
Arquivo(s): updatequery.php
Parâmetro(s): queryx, ansx
Método: POST · Autenticação: Nenhuma para injetar (via item 00)
```

### Requisição de exemplo

```http
POST /updatequery.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<sessão — dispensável via item 00 (Broken Access Control)>

queryx=<valor>&ansx=<valor>
```

### Resposta observada

```text
payload refletido SEM encoding: </textarea><script>alert(document.domain)</script>
```

### Resultado

Reproduzido ao vivo no laboratório autorizado (http://192.168.95.131:9292/) em 02/08/2026, de forma não-destrutiva. O comportamento observado confirma a falha de Stored / Persistent Cross-Site Scripting.

**a) Execução no navegador** (resposta real do servidor renderizada, com faixa de evidência):

![Evidência de execução web — 09-updatequery-stored-xss](evidencia-web-09-updatequery-stored-xss.png)

**b) Linha de código vulnerável** (`updatequery.php`):

![Evidência de código-fonte — 09-updatequery-stored-xss](evidencia-codigo-09-updatequery-stored-xss.png)

> **Nota:** as credenciais/PII exibidas pertencem ao dataset de teste do laboratório. Remova segredos reais antes de qualquer publicação externa.

---

## 8. Prova de conceito

A prova de conceito abaixo demonstra apenas o comportamento vulnerável e deve ser utilizada exclusivamente em ambientes autorizados. Script executável e não-destrutivo: **`poc.sh`**.

```bash
# ciclo não-destrutivo (captura->injeta->verifica->restaura):
python3 ../_lib/xss_poc.py "http://192.168.95.131:9292" "updatequery.php?..." \
  queryx '</textarea><script>alert(document.domain)</script>' --fields queryx,ansx --textarea
```

### Resultado esperado

```text
payload refletido SEM encoding: </textarea><script>alert(document.domain)</script>
```


### Limitações da PoC

- Não causa indisponibilidade intencional.
- Não remove ou modifica dados de terceiros (injeções de estado são restauradas; error-based aborta antes de persistir).
- Não cria persistência ou backdoor.
- Não contém credenciais reais (apenas dados do laboratório de teste).
- Não automatiza exploração em massa.

---

## 9. Passos para reprodução

1. Acesse uma instância de **CloudClassroom-PHP-Project 1.0**.
2. Configure o pré-requisito: Nenhuma para injetar (item 00). Vítima autenticada (admin/faculty) precisa visualizar o registro.
3. Acesse o componente **updatequery.php** (parâmetro(s): queryx, ansx).
4. Envie a requisição/entrada descrita nas seções 7 e 8.
5. Observe o resultado vulnerável: payload refletido SEM encoding: </textarea><script>alert(document.domain)</script>
6. Compare com o comportamento seguro esperado (entrada devidamente validada/sanitizada/autorizada, sem reflexão do payload nem execução indevida).

---

## 10. Mitigação

Até que a correção definitiva seja aplicada, recomenda-se:

- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

Medidas compensatórias adicionais:

- Restringir o acesso ao componente afetado (rede/ACL/WAF).
- Aplicar regras de WAF/proxy reverso para bloquear padrões de ataque conhecidos.
- Revisar permissões e privilégios associados; invalidar sessões/credenciais potencialmente expostas.
- Manter logs e evidências para investigação.

> As mitigações reduzem o risco, mas podem não eliminar completamente a vulnerabilidade.

---

## 11. Correção

**Nenhuma correção oficial disponível até a data deste advisory (produto unpatched).**

Quando disponibilizada, recomenda-se:

1. Atualizar para a versão corrigida ou superior.
2. Reiniciar os serviços afetados, quando necessário.
3. Invalidar sessões e credenciais antigas.
4. Revisar logs anteriores à atualização.
5. Confirmar que o comportamento vulnerável não pode mais ser reproduzido.

### Alteração recomendada ao fornecedor

- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

---

## 12. Detecção e indicadores

Possíveis indicadores de exploração:

- Valores persistidos via `updatequery.php` contendo `<script`, `onerror=`, `onload=`, `<svg` ou `</textarea>`.

### Exemplo de busca em logs

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "updatequery.php"
```

---

## 13. Timeline de divulgação

| Data | Evento |
|---|---|
| 02/08/2026 | Vulnerabilidade identificada (análise estática) |
| 02/08/2026 | Confirmada dinamicamente no laboratório autorizado |
| 02/08/2026 | Re-validada ao vivo com evidências (navegador + código) |
| 02/08/2026 | Pacote de divulgação preparado (este advisory) |
| (pendente) | Notificação ao fornecedor |
| (pendente) | CVE solicitada/reservada |
| (pendente) | Correção disponibilizada |
| (pendente) | Publicação do advisory |

---

## 14. Comunicação com o fornecedor

- **Fornecedor:** Vishal Mathur (`mathurvishal`)
- **Canal utilizado:** GitHub Security Advisory privado do repositório / e-mail do mantenedor (ver `VENDOR-EMAIL.md`)
- **Data da primeira notificação:** (pendente)
- **Status da resposta:** Aguardando notificação/retorno
- **Posicionamento do fornecedor:** N/A até o momento

---

## 15. Créditos

A vulnerabilidade foi identificada e reportada por:

- **Pesquisador:** vinniboy021@gmail.com
- **Organização:** Pesquisa independente de segurança
- **Contato:** vinniboy021@gmail.com

---

## 16. Referências

- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/
- https://github.com/mathurvishal/CloudClassroom-PHP-Project
- https://www.first.org/cvss/calculator/3.1

---

## 17. Histórico de revisões

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 02/08/2026 | Publicação inicial |

---

## 18. Aviso legal

Este advisory é publicado com finalidade educacional, defensiva e de melhoria da segurança.

As informações apresentadas foram obtidas em ambiente autorizado e divulgadas de forma responsável ou coordenada. O autor não incentiva o uso destas informações para acesso não autorizado, interrupção de serviços, violação de privacidade ou qualquer atividade ilegal.

A utilização das informações deste documento é de responsabilidade exclusiva do leitor.

---

## 19. Contato

Para correções, atualizações ou informações adicionais:

- **E-mail:** vinniboy021@gmail.com
- **Repositório:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
