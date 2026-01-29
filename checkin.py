#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import re
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from py_mini_racer import MiniRacer

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'

WAF_JS_BOOTSTRAP = """
var __cookieStore = {};
var document = {};
Object.defineProperty(document, "cookie", {
  get: function() {
    return Object.keys(__cookieStore).map(function(key) {
      return key + "=" + __cookieStore[key];
    }).join("; ");
  },
  set: function(val) {
    var mainPart = val.split(";")[0];
    var idx = mainPart.indexOf("=");
    if (idx > 0) {
      var key = mainPart.slice(0, idx).trim();
      var value = mainPart.slice(idx + 1).trim();
      __cookieStore[key] = value;
    }
  }
});
document.location = { reload: function() {}, href: "" };
var location = document.location;
var window = this;
var self = this;
"""


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'⚠️  保存余额记录失败: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


def _execute_waf_script(script_content: str) -> tuple[dict[str, str] | None, str | None]:
	"""执行单个 WAF 挑战脚本并收集 cookies"""
	ctx = MiniRacer()
	ctx.eval(WAF_JS_BOOTSTRAP)

	try:
		ctx.eval(f'(function(){{{script_content}\n}})();')
	except Exception as e:
		return None, str(e)

	try:
		cookie_json = ctx.eval('JSON.stringify(__cookieStore)')
	except Exception as e:
		return None, f'读取 cookie 失败: {e}'

	cookie_map = json.loads(cookie_json) if cookie_json else {}
	if cookie_map:
		return cookie_map, None
	return None, '脚本执行完成但未设置 cookie'


async def get_waf_cookies_via_js_challenge(account_name: str, login_url: str, required_cookies: list[str]) -> dict | None:
	"""通过执行 JS 挑战获取 WAF cookies"""
	print(f'   ├─ 🔐 正在获取 WAF 认证...')

	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.9',
	}

	try:
		async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
			response = await client.get(login_url, headers=headers)
	except Exception as e:
		print(f'   ├─ ❌ WAF 页面请求失败: {e}')
		return None

	collected_cookies = dict(response.cookies)

	scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', response.text, flags=re.IGNORECASE)
	for script_content in scripts:
		if not script_content.strip():
			continue
		cookie_map, _ = _execute_waf_script(script_content)
		if cookie_map:
			collected_cookies.update(cookie_map)

	if not collected_cookies:
		print(f'   ├─ ❌ 未能获取任何 WAF cookies')
		return None

	missing_cookies = [c for c in required_cookies if c not in collected_cookies]
	if missing_cookies:
		print(f'   ├─ ❌ 缺少必需的 cookies: {missing_cookies}')
		return None

	print(f'   ├─ ✅ WAF 认证成功 (获取 {len(collected_cookies)} 个 cookies)')
	return collected_cookies


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f'💰 余额: ${quota}  |  已用: ${used_quota}',
				}
		return {'success': False, 'error': f'获取用户信息失败: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'获取用户信息失败: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_via_js_challenge(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			return None

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'   ├─ 📝 正在签到...')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				return True
			else:
				error_msg = result.get('msg', result.get('message', '未知错误'))
				print(f'   ├─ ❌ 签到失败: {error_msg}')
				return False
		except json.JSONDecodeError:
			if 'success' in response.text.lower():
				return True
			else:
				print(f'   ├─ ❌ 签到失败: 响应格式异常')
				return False
	else:
		print(f'   ├─ ❌ 签到失败: HTTP {response.status_code}')
		return False


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n📌 {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'   └─ ❌ 服务商 "{account.provider}" 未配置')
		return False, None

	print(f'   ├─ 🌐 服务商: {account.provider} ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'   └─ ❌ 账号配置格式错误')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		print(f'   └─ ❌ WAF 认证失败')
		return False, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info = get_user_info(client, headers, user_info_url)
		if user_info and user_info.get('success'):
			print(f'   ├─ {user_info["display"]}')
		elif user_info:
			print(f'   ├─ ⚠️  {user_info.get("error", "未知错误")}')

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			if success:
				print(f'   └─ ✅ 签到成功')
			else:
				print(f'   └─ ❌ 签到失败')
			return success, user_info
		else:
			print(f'   └─ ✅ 自动签到完成')
			return True, user_info

	except Exception as e:
		print(f'   └─ ❌ 处理异常: {str(e)[:50]}...')
		return False, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('╔════════════════════════════════════════════════════════════╗')
	print('║           AnyRouter 自动签到 · JS Challenge 版             ║')
	print('╚════════════════════════════════════════════════════════════╝')
	print(f'⏰ 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'📦 已加载 {len(app_config.providers)} 个服务商配置')

	accounts = load_accounts_config()
	if not accounts:
		print('❌ 账号配置加载失败，程序退出')
		sys.exit(1)

	print(f'👥 发现 {len(accounts)} 个账号配置')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	need_notify = False
	balance_changed = False

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True

			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '✅' if success else '❌'
				account_result = f'{status} {account_name}'
				if user_info and user_info.get('success'):
					account_result += f'\n{user_info["display"]}'
				elif user_info:
					account_result += f'\n{user_info.get("error", "未知错误")}'
				notification_content.append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'   └─ ❌ 处理异常: {e}')
			need_notify = True
			notification_content.append(f'❌ {account_name} 异常: {str(e)[:50]}...')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			balance_changed = True
			need_notify = True
		elif current_balance_hash != last_balance_hash:
			balance_changed = True
			need_notify = True

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = account.get_display_name(i)
				account_result = f'💰 {account_name}'
				account_result += f'\n余额: ${current_balances[account_key]["quota"]}  |  已用: ${current_balances[account_key]["used"]}'
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	# 打印统计
	print('\n' + '─' * 50)
	print(f'📊 签到统计: 成功 {success_count}/{total_count}  |  失败 {total_count - success_count}/{total_count}')

	if need_notify and notification_content:
		summary = [
			f'📊 签到统计',
			f'✅ 成功: {success_count}/{total_count}',
			f'❌ 失败: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('🎉 全部签到成功!')
		elif success_count > 0:
			summary.append('⚠️ 部分签到成功')
		else:
			summary.append('💥 全部签到失败')

		time_info = f'⏰ 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		notify.push_message('AnyRouter 签到提醒', notify_content, msg_type='text')
		print('📨 已发送通知 (签到失败或余额变化)')
	else:
		print('✅ 全部成功且余额无变化，跳过通知')

	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n⚠️  用户中断')
		sys.exit(1)
	except Exception as e:
		print(f'\n❌ 程序异常: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
