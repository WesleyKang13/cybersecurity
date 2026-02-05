import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head } from '@inertiajs/react';
import { useState } from 'react';
import axios from 'axios';
import { ShieldAlert, CheckCircle, Search, Smartphone, AlertTriangle, XCircle, Phone } from 'lucide-react'; // Added 'Phone' icon

export default function SmsScanner({ auth }) {
    // 1. Updated State to include 'sender'
    const [sender, setSender] = useState('');
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleScan = async (e) => {
        e.preventDefault();
        if (!message.trim() || !sender.trim()) return;

        setLoading(true);
        setResult(null);
        setError(null);

        try {
            // 👇 FIXED: Changed 'body' to 'message' to match the Controller
            const response = await axios.post(route('sms.analyze'), {
                sender: sender,
                message: message
            });
            setResult(response.data);
        } catch (err) {
            console.error(err);
            // Better error handling for Laravel Validation errors (422)
            if (err.response && err.response.status === 422) {
                setError(err.response.data.message || "Validation failed. Please check inputs.");
            } else {
                setError(err.response?.data?.error || "Analysis failed. Please check your connection and API Key.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">SMS & Text Scanner</h2>}
        >
            <Head title="SMS Scanner" />

            <div className="py-12">
                <div className="max-w-4xl mx-auto sm:px-6 lg:px-8">

                    {/* Input Section */}
                    <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6 mb-6">
                        <div className="flex items-center mb-6">
                            <Smartphone className="w-6 h-6 text-indigo-500 mr-2" />
                            <h3 className="text-lg font-medium text-gray-900">Scan Message</h3>
                        </div>

                        <form onSubmit={handleScan} className="space-y-6">

                            {/* NEW: Sender Input Field */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">
                                    Sender Name or Number
                                </label>
                                <div className="relative rounded-md shadow-sm">
                                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                                        <Phone className="h-5 w-5 text-gray-400" />
                                    </div>
                                    <input
                                        type="text"
                                        className="block w-full rounded-md border-gray-300 pl-10 py-2 focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm shadow-sm border"
                                        placeholder="e.g. DHL, +353871234567, Unknown Number"
                                        value={sender}
                                        onChange={(e) => setSender(e.target.value)}
                                        required
                                    />
                                </div>
                            </div>

                            {/* Existing: Message Body Field */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">
                                    Message Text
                                </label>
                                <textarea
                                    className="w-full h-32 p-4 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 shadow-sm"
                                    placeholder="Example: 'Your package is on hold. Click here to update delivery details...'"
                                    value={message}
                                    onChange={(e) => setMessage(e.target.value)}
                                    required
                                ></textarea>
                            </div>

                            <div className="flex justify-end">
                                <button
                                    type="submit"
                                    disabled={loading || !message || !sender}
                                    className={`flex items-center px-6 py-2 rounded-md text-white font-semibold transition ${
                                        loading || !message || !sender ? 'bg-gray-400 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'
                                    }`}
                                >
                                    {loading ? 'Analyzing...' : (
                                        <>
                                            <Search className="w-4 h-4 mr-2" />
                                            Analyze Threat
                                        </>
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>

                    {/* Error Alert Message */}
                    {error && (
                        <div className="mb-6 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative flex items-center">
                            <XCircle className="w-5 h-5 mr-2" />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Results Section */}
                    {result && (
                        <div className={`overflow-hidden shadow-sm sm:rounded-lg p-6 border-l-8 ${result.is_threat ? 'bg-red-50 border-red-500' : 'bg-green-50 border-green-500'}`}>
                            <div className="flex items-start">
                                <div className="flex-shrink-0">
                                    {result.is_threat ? (
                                        <AlertTriangle className="h-10 w-10 text-red-500" />
                                    ) : (
                                        <CheckCircle className="h-10 w-10 text-green-500" />
                                    )}
                                </div>
                                <div className="ml-4 w-full">
                                    <h3 className={`text-xl font-bold ${result.is_threat ? 'text-red-800' : 'text-green-800'}`}>
                                        {result.is_threat ? 'Potential Threat Detected' : 'Message Appears Safe'}
                                    </h3>

                                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="bg-white p-4 rounded shadow-sm">
                                            <p className="text-sm text-gray-500 uppercase font-bold">Risk Score</p>
                                            <p className={`text-2xl font-bold ${result.risk_score > 50 ? 'text-red-600' : 'text-green-600'}`}>
                                                {result.risk_score}/100
                                            </p>
                                        </div>
                                        <div className="bg-white p-4 rounded shadow-sm">
                                            <p className="text-sm text-gray-500 uppercase font-bold">Category</p>
                                            <p className="text-lg font-medium text-gray-800">{result.type}</p>
                                        </div>
                                    </div>

                                    <div className="mt-4">
                                        <p className="text-sm text-gray-500 uppercase font-bold">Analysis</p>
                                        <p className="text-gray-700 mt-1">{result.explanation}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
