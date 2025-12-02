import React, { useState, useEffect } from 'react';
import { Target, TrendingUp, Plus } from 'lucide-react';
import axios from 'axios';

interface Campaign {
  campaign_id: string;
  name: string;
  targets: string[];
  sector: string;
  status: string;
}

const CampaignManager: React.FC = () => {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newCampaign, setNewCampaign] = useState({
    name: '',
    targets: [''],
    sector: 'unknown'
  });
  const [loading, setLoading] = useState(false);

  const sectors = [
    'unknown', 'finance', 'healthcare', 'technology', 'retail',
    'government', 'education', 'energy', 'telecom', 'manufacturing'
  ];

  const createCampaign = async () => {
    if (!newCampaign.name.trim()) {
      alert('Campaign name is required');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('/api/intelligence/campaigns', {
        name: newCampaign.name,
        targets: newCampaign.targets.filter(t => t.trim()),
        sector: newCampaign.sector
      });
      
      setCampaigns([...campaigns, response.data]);
      setNewCampaign({ name: '', targets: [''], sector: 'unknown' });
      setShowCreate(false);
    } catch (error) {
      console.error('Failed to create campaign:', error);
      alert('Failed to create campaign');
    } finally {
      setLoading(false);
    }
  };

  const addTargetField = () => {
    setNewCampaign({
      ...newCampaign,
      targets: [...newCampaign.targets, '']
    });
  };

  const updateTarget = (index: number, value: string) => {
    const newTargets = [...newCampaign.targets];
    newTargets[index] = value;
    setNewCampaign({ ...newCampaign, targets: newTargets });
  };

  return (
    <div className="campaign-manager bg-gray-900 border border-gray-800 rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Target className="w-6 h-6 text-cyan-400" />
          <h2 className="text-2xl font-bold text-cyan-400">í³Š Campaign Intelligence</h2>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Campaign
        </button>
      </div>

      {/* Create Campaign Form */}
      {showCreate && (
        <div className="create-campaign bg-gray-800/50 border border-gray-700 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-100 mb-4">Create New Campaign</h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Campaign Name
              </label>
              <input
                type="text"
                placeholder="e.g., Q4 Healthcare Assessment"
                value={newCampaign.name}
                onChange={e => setNewCampaign({ ...newCampaign, name: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Sector
              </label>
              <select
                value={newCampaign.sector}
                onChange={e => setNewCampaign({ ...newCampaign, sector: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:outline-none focus:border-cyan-500"
              >
                {sectors.map(s => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Targets
              </label>
              <div className="space-y-2">
                {newCampaign.targets.map((target, i) => (
                  <input
                    key={i}
                    type="text"
                    placeholder={`Target ${i + 1} (URL or IP)`}
                    value={target}
                    onChange={e => updateTarget(i, e.target.value)}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:outline-none focus:border-cyan-500"
                  />
                ))}
                <button
                  onClick={addTargetField}
                  className="text-sm text-cyan-400 hover:text-cyan-300 py-2"
                >
                  + Add Target
                </button>
              </div>
            </div>

            <div className="flex gap-2 pt-4">
              <button
                onClick={createCampaign}
                disabled={loading}
                className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg transition-colors"
              >
                {loading ? 'Creating...' : 'Create Campaign'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Campaign List */}
      <div className="campaigns-list">
        {campaigns.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <p>No campaigns created yet.</p>
            <p className="text-sm mt-2">Create a campaign to start multi-target assessments.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {campaigns.map(campaign => (
              <div
                key={campaign.campaign_id}
                className="campaign-card bg-gray-800/50 border border-gray-700 rounded-lg p-4 hover:border-cyan-600 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <h3 className="text-lg font-semibold text-cyan-300">{campaign.name}</h3>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    campaign.status === 'running'
                      ? 'bg-green-900/30 text-green-300'
                      : campaign.status === 'pending'
                      ? 'bg-yellow-900/30 text-yellow-300'
                      : 'bg-gray-700 text-gray-300'
                  }`}>
                    {campaign.status}
                  </span>
                </div>

                <div className="mb-3">
                  <p className="text-xs text-gray-400 mb-1">Sector</p>
                  <p className="text-sm text-gray-200 capitalize">{campaign.sector}</p>
                </div>

                <div className="mb-3">
                  <p className="text-xs text-gray-400 mb-1">Targets ({campaign.targets.length})</p>
                  <div className="flex flex-wrap gap-1">
                    {campaign.targets.slice(0, 2).map((t, i) => (
                      <span key={i} className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                        {t.split('//').pop()?.split('/')[0] || t}
                      </span>
                    ))}
                    {campaign.targets.length > 2 && (
                      <span className="px-2 py-1 bg-gray-700 text-gray-400 rounded text-xs">
                        +{campaign.targets.length - 2} more
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex gap-2 pt-2 border-t border-gray-700">
                  <button className="flex-1 px-3 py-2 text-xs bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 rounded transition-colors">
                    <TrendingUp className="w-3 h-3 inline mr-1" />
                    View Insights
                  </button>
                  <button className="flex-1 px-3 py-2 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors">
                    Optimize Order
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default CampaignManager;
