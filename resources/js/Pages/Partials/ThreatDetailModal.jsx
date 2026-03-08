import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import DangerButton from '@/Components/DangerButton';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'; // Removed Mail, added AlertTriangle

export default function ThreatDetailModal({ show, onClose, email }) {
    console.log("Email data received by Modal:", email);
    // Merge defaults with incoming data
    const safeEmail = {
        subject: 'Loading...',
        sender: 'Unknown Sender',
        severity: 'clean',
        snippet: 'No content available for this email.',
        reason: 'No analysis provided.',
        detection_layer: 'Unknown', // Added default for the new column
        ...email
    };

    return (
        <Modal show={show} onClose={onClose} maxWidth="lg">
            <div className="relative z-[999] bg-white dark:bg-gray-800 rounded-lg shadow-xl overflow-hidden">

                {/* 1. HEADER */}
                <div className="p-6 pb-4 border-b border-gray-100 dark:border-gray-700 flex justify-between items-center">
                    <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100 flex items-center">
                        {safeEmail.severity === 'high' ? (
                            <ShieldAlert className="w-6 h-6 text-red-600 mr-2" />
                        ) : (
                            <ShieldCheck className="w-6 h-6 text-green-600 mr-2" />
                        )}
                        Threat Analysis
                    </h2>
                    <span className={`px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wide shadow-sm ${
                        safeEmail.severity === 'high' ? 'bg-red-100 text-red-800 border border-red-200' :
                        safeEmail.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 border border-yellow-200' :
                        'bg-green-100 text-green-800 border border-green-200'
                    }`}>
                        {safeEmail.severity}
                    </span>
                </div>

                {/* 2. BODY CONTENT */}
                <div className="p-6 space-y-4">
                    {/* Metadata Box */}
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

                        {/* DYNAMIC VERDICT BOX - With Fallback for old null records */}
                        <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                            {safeEmail.detection_layer?.includes('Layer 1') || safeEmail.reason?.includes('Auto-cleared') ? (
                                <div className="flex items-start">
                                    <ShieldCheck className="w-4 h-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" />
                                    <div>
                                        <span className="text-xs font-bold text-green-600 uppercase block mb-1">System Verdict (Layer 1)</span>
                                        <p className="text-sm font-medium text-green-700 dark:text-green-400">
                                            ✅ NO AI NEEDED: This email is safe as it was caught at Layer 1 (Trusted Whitelist).
                                        </p>
                                    </div>
                                </div>
                            ) : safeEmail.detection_layer?.includes('Layer 2.5 (VirusTotal API)') ? (
                                // 👇 THE NEW LAYER 2.5 VIRUSTOTAL LOGIC
                                <div className="flex items-start">
                                    <AlertTriangle className="w-4 h-4 text-purple-500 mt-0.5 mr-2 flex-shrink-0" />
                                    <div>
                                        <span className="text-xs font-bold text-purple-600 uppercase block mb-1">Sandbox Verdict (Layer 2.5)</span>
                                        <p className="text-sm font-medium text-purple-700 dark:text-purple-400">
                                            🦠 {safeEmail.reason}
                                        </p>
                                    </div>
                                </div>
                            ) : safeEmail.detection_layer?.includes('Layer 2') || safeEmail.reason?.includes('Manual Rule') ? (
                                <div className="flex items-start">
                                    <ShieldAlert className="w-4 h-4 text-red-500 mt-0.5 mr-2 flex-shrink-0" />
                                    <div>
                                        <span className="text-xs font-bold text-red-600 uppercase block mb-1">System Verdict (Layer 2)</span>
                                        <p className="text-sm font-medium text-red-700 dark:text-red-400">
                                            🛑 NO AI NEEDED: Caught at Layer 2 (Manual Security Rules) due to suspicious keywords.
                                        </p>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex items-start">
                                    <AlertTriangle className="w-4 h-4 text-indigo-500 mt-0.5 mr-2 flex-shrink-0" />
                                    <div>
                                        <span className="text-xs font-bold text-indigo-600 uppercase block mb-1">AI Verdict (Layer 3)</span>
                                        <p className="text-sm italic text-gray-700 dark:text-gray-300">
                                            🤖 "{safeEmail.reason || 'No specific reason provided.'}"
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Email Snippet */}
                    <div>
                        <h3 className="text-xs font-medium text-gray-500 mb-1.5 uppercase">Email Content</h3>
                        <div className="p-3 bg-gray-100 dark:bg-black/20 border border-gray-200 dark:border-gray-700 rounded text-sm text-gray-600 dark:text-gray-400 font-mono text-xs overflow-y-auto max-h-32 shadow-inner">
                            {safeEmail.snippet}
                        </div>
                    </div>
                </div>

                {/* 3. FOOTER */}
                <div className="px-6 py-4 bg-gray-50 dark:bg-gray-700/50 flex justify-end space-x-3 border-t border-gray-100 dark:border-gray-700">
                    <SecondaryButton onClick={onClose}>
                        Close
                    </SecondaryButton>
                </div>
            </div>
        </Modal>
    );
}
