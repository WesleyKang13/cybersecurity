import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import ThreatScanResultCard from '@/Pages/Partials/ThreatScanResultCard';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export default function ThreatDetailModal({ show, onClose, email }) {
    const safeEmail = {
        subject: 'Loading...',
        sender: 'Unknown Sender',
        severity: 'clean',
        snippet: 'No content available for this email.',
        reason: 'No analysis provided.',
        detection_layer: 'Unknown',
        threat_category: 'None',
        analysis_chain: [],
        origin_trace: null,
        verdict: null,
        risk_score: 0,
        ...email,
    };

    const normalizedVerdict = safeEmail.verdict
        || (safeEmail.severity === 'high'
            ? 'MALICIOUS'
            : safeEmail.severity === 'medium'
                ? 'SUSPICIOUS'
                : 'CLEAN');

    const scanResult = {
        verdict: normalizedVerdict,
        risk_score: safeEmail.risk_score,
        severity: safeEmail.severity,
        reason: safeEmail.final_reasoning || safeEmail.reason,
        threat_category: safeEmail.threat_category,
        analysis_chain: safeEmail.analysis_chain,
        origin_trace: safeEmail.origin_trace,
    };

    return (
        <Modal show={show} onClose={onClose} maxWidth="4xl">
            <div className="relative z-[999] flex max-h-[85vh] w-full flex-col overflow-hidden bg-white dark:bg-gray-800">

                <div className="p-6 pb-4 border-b border-gray-100 dark:border-gray-700 flex justify-between items-center">
                    <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100 flex items-center">
                        {safeEmail.severity === 'high' ? (
                            <ShieldAlert className="w-6 h-6 text-red-600 mr-2" />
                        ) : (
                            <ShieldCheck className="w-6 h-6 text-green-600 mr-2" />
                        )}
                        Email Security Scan
                    </h2>
                </div>

                <div className="space-y-4 overflow-y-auto p-6">
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-md p-4 border border-gray-200 dark:border-gray-700">
                        <div className="grid grid-cols-1 gap-3">
                            <div>
                                <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Subject</span>
                                <p className="text-sm font-semibold text-gray-800 dark:text-gray-200 leading-tight mt-0.5">
                                    {safeEmail.subject}
                                </p>
                            </div>
                            <div>
                                <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Sender</span>
                                <p className="text-xs font-mono text-gray-500 dark:text-gray-400 mt-0.5 truncate">
                                    {safeEmail.sender}
                                </p>
                            </div>
                        </div>
                    </div>

                    <ThreatScanResultCard result={scanResult} />

                    <div>
                        <h3 className="text-xs font-medium text-gray-500 mb-1.5 uppercase">Email Content</h3>
                        <div className="p-3 bg-gray-100 dark:bg-black/20 border border-gray-200 dark:border-gray-700 rounded text-sm text-gray-600 dark:text-gray-400 font-mono text-xs overflow-y-auto max-h-32 shadow-inner">
                            {safeEmail.snippet}
                        </div>
                    </div>
                </div>

                <div className="px-6 py-4 bg-gray-50 dark:bg-gray-700/50 flex justify-end space-x-3 border-t border-gray-100 dark:border-gray-700">
                    <SecondaryButton onClick={onClose}>
                        Close
                    </SecondaryButton>
                </div>
            </div>
        </Modal>
    );
}
