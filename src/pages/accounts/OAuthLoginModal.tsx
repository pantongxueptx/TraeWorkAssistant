import { useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { ArrowRight, ExternalLink } from 'lucide-react';
import { Modal } from '../../components/ui';
import { api } from '../../lib/tauri';
import { useAppStore } from '../../store';
import type { GroupView, OAuthCallbackEvent } from '../../types';

export function OAuthLoginModal({
  open,
  onClose,
  groups,
  onLogin,
}: {
  open: boolean;
  onClose: () => void;
  groups: GroupView[];
  onLogin: (
    callbackUrl: string,
    accountName?: string,
    groupId?: string,
  ) => Promise<void>;
}) {
  const [step, setStep] = useState(1);
  const [callbackUrl, setCallbackUrl] = useState('');
  const [accountName, setAccountName] = useState('');
  const [gid, setGid] = useState('');
  const [busy, setBusy] = useState(false);
  const [opening, setOpening] = useState(false);
  const toast = useAppStore((s) => s.pushToast);

  useEffect(() => {
    if (!open) {
      setStep(1);
      setCallbackUrl('');
      setAccountName('');
      setGid('');
      setBusy(false);
      setOpening(false);
      // F-74 批次1/2：Modal 关闭（含登录成功后 Accounts 收起弹窗）即收尾——
      // 停回环监听、还原暂停前的系统代理，均幂等无害
      void api.oauth.loopbackStop().catch(() => {});
      void api.oauth.proxyRestore().catch(() => {});
    }
  }, [open]);

  const openLoginPage = async () => {
    setOpening(true);
    try {
      // 先起 127.0.0.1:17388 回环监听 + 临时绕开系统代理（F-74 缺口1/2）：
      // 系统代理无论是本软件 MITM（CA 未信任撞 SSL）还是指向已死端口（请求无限挂起），
      // 都会让授权页永远加载不出来——issue #10「一直处于加载中」的直接来源
      await api.oauth.loopbackStart();
      await api.oauth.proxyPause();
      const { url } = await api.oauth.getLoginUrl();
      const { open } = await import('@tauri-apps/plugin-shell');
      await open(url);
      setStep(2);
    } catch (err) {
      toast('error', `打开登录页失败：${String(err)}`);
    } finally {
      setOpening(false);
    }
  };

  const finish = async (rawUrl?: string) => {
    const url = (rawUrl ?? callbackUrl).trim();
    if (!url) return;
    setBusy(true);
    try {
      await onLogin(
        url,
        accountName.trim() || undefined,
        gid || undefined,
      );
    } finally {
      setBusy(false);
    }
  };

  // 自动接续（F-74 批次1）：监听回环监听器的回调事件，自动填入并完成登录。
  // 经 ref 取最新闭包，避免 effect 依赖变化导致监听器反复重挂
  const finishRef = useRef(finish);
  finishRef.current = finish;
  useEffect(() => {
    if (!open) return;
    let alive = true;
    let unlisten: (() => void) | undefined;
    void listen<OAuthCallbackEvent>('oauth-callback', (e) => {
      const url = e.payload?.url?.trim();
      if (url) void finishRef.current(url);
    }).then((f) => {
      if (alive) unlisten = f;
      else f();
    });
    return () => {
      alive = false;
      unlisten?.();
    };
  }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="OAuth 登录"
      footer={
        <>
          {step > 1 && (
            <button
              onClick={() => setStep((s) => Math.max(1, s - 1))}
              className="btn-ghost"
              disabled={busy || opening}
            >
              上一步
            </button>
          )}
          <button onClick={onClose} className="btn-ghost" disabled={busy || opening}>
            取消
          </button>
          {step === 1 && (
            <button
              onClick={openLoginPage}
              disabled={opening}
              className="btn-primary"
            >
              {opening ? '正在打开...' : '打开登录页'}
              {!opening && <ExternalLink size={14} />}
            </button>
          )}
          {step === 2 && (
            <button
              onClick={() => setStep(3)}
              disabled={!callbackUrl.trim()}
              className="btn-primary"
            >
              下一步 <ArrowRight size={14} />
            </button>
          )}
          {step === 3 && (
            <button
              onClick={() => void finish()}
              disabled={busy || !callbackUrl.trim()}
              className="btn-primary"
            >
              {busy ? '登录中...' : '完成登录'}
            </button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        {/* 步骤指示器 */}
        <div className="flex items-center gap-2">
          <div
            className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold ${
              step >= 1
                ? 'bg-brand-500 text-white'
                : 'bg-slate-200 text-slate-500 dark:bg-zinc-700'
            }`}
          >
            1
          </div>
          <div
            className={`h-0.5 w-8 ${step > 1 ? 'bg-brand-500' : 'bg-slate-200 dark:bg-zinc-700'}`}
          />
          <div
            className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold ${
              step >= 2
                ? 'bg-brand-500 text-white'
                : 'bg-slate-200 text-slate-500 dark:bg-zinc-700'
            }`}
          >
            2
          </div>
          <div
            className={`h-0.5 w-8 ${step > 2 ? 'bg-brand-500' : 'bg-slate-200 dark:bg-zinc-700'}`}
          />
          <div
            className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold ${
              step >= 3
                ? 'bg-brand-500 text-white'
                : 'bg-slate-200 text-slate-500 dark:bg-zinc-700'
            }`}
          >
            3
          </div>
        </div>

        {step === 1 && (
          <div className="space-y-2 text-sm text-slate-600 dark:text-zinc-300">
            <div>点击「打开登录页」在浏览器中完成 OAuth 授权。登录期间会临时绕开系统代理（结束后自动还原），并已在本机 17388 端口自动接收回调。</div>
            <div>授权完成后应用会<b>自动添加账号</b>，通常无需手动操作。</div>
          </div>
        )}

        {step === 2 && (
          <div>
            <label className="label">回调 URL（自动获取中，无需手动填写）</label>
            <textarea
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              className="input min-h-[100px] font-mono text-xs"
              placeholder="登录完成后会自动填入；若浏览器提示无法访问，也可手动复制地址栏 URL 粘贴到此处"
            />
            <p className="mt-2 text-xs text-slate-400">
              自动接收失败时的兜底：浏览器跳转到 http://127.0.0.1:17388/authorize?... 页面后（页面可能显示无法访问），复制地址栏完整 URL 粘贴到此处，点「下一步」按引导完成
            </p>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-3">
            <div>
              <label className="label">账号备注名（可选）</label>
              <input
                value={accountName}
                onChange={(e) => setAccountName(e.target.value)}
                className="input"
                placeholder="例如：me_1676"
              />
            </div>
            <div>
              <label className="label">分组（可选）</label>
              <select
                value={gid}
                onChange={(e) => setGid(e.target.value)}
                className="input"
              >
                <option value="">不分组</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
