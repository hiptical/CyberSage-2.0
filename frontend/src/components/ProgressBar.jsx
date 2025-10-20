import React from 'react';

const ProgressBar = ({ progress, phase }) => {
  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-purple-500/30">
      <div className="flex justify-between mb-3">
        <span className="text-gray-300 font-medium">{phase}</span>
        <span className="text-purple-400 font-bold text-lg">{progress}%</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-4 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-purple-500 via-pink-500 to-purple-500 transition-all duration-500 ease-out animate-gradient"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="mt-3 flex items-center text-sm text-gray-400">
        <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse mr-2"></div>
        Analyzing security posture...
      </div>
    </div>
  );
};

export default ProgressBar;