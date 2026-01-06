
#include "stratum.h"

double client_normalize_difficulty(double difficulty)
{
	// Important: the historical quantization logic ("*1000/2" then floor)
	// collapses very small difficulties (<0.002) down to zero, which breaks
	// vardiff for low-diff coins (diff_min like 2e-7). Keep precision for
	// sub-1 difficulties and only apply coarse rounding for >= 1.
	if(difficulty < g_stratum_min_diff) difficulty = g_stratum_min_diff;
	if(difficulty > g_stratum_max_diff) difficulty = g_stratum_max_diff;

	if(difficulty < 1.0)
	{
		// Round to 1e-9 to avoid float noise while keeping tiny diffs intact.
		const double q = 1e-9;
		difficulty = floor(difficulty / q + 0.5) * q;
	}
	else
	{
		// Keep the historical even-number behaviour at high diff.
		difficulty = floor(difficulty/2) * 2;
	}

	if(difficulty < g_stratum_min_diff) difficulty = g_stratum_min_diff;
	if(difficulty > g_stratum_max_diff) difficulty = g_stratum_max_diff;
	return difficulty;
}

void client_record_difficulty(YAAMP_CLIENT *client)
{
	if(client->difficulty_remote)
	{
		client->last_submit_time = current_timestamp();
		return;
	}

	int e = current_timestamp() - client->last_submit_time;
	if(e < 500) e = 500;
	int p = 5;

	client->shares_per_minute = (client->shares_per_minute * (100 - p) + 60*1000*p/e) / 100;
	client->last_submit_time = current_timestamp();

//	debuglog("client->shares_per_minute %f\n", client->shares_per_minute);
}

void client_change_difficulty(YAAMP_CLIENT *client, double difficulty)
{
	if(difficulty <= 0) return;

	difficulty = client_normalize_difficulty(difficulty);
	if(difficulty <= 0) return;

//	debuglog("change diff to %f %f\n", difficulty, client->difficulty_actual);
	if(difficulty == client->difficulty_actual) return;

	client->difficulty_actual = difficulty;
	client_send_difficulty(client, difficulty);
}

void client_adjust_difficulty(YAAMP_CLIENT *client)
{
	if(client->difficulty_remote) {
		client_change_difficulty(client, client->difficulty_remote);
		return;
	}

	if(client->difficulty_fixed)
		return;

	long long now = current_timestamp();
	if(client->last_vardiff_time == 0)
		client->last_vardiff_time = now;

	// Retarget at most once per interval
	if(now - client->last_vardiff_time < g_vardiff_retarget_ms)
		return;

	// Idle-decay: if miner hasn't submitted an accepted share recently,
	// treat effective SPM as lower so diff can step down.
	long long idle_ms = now - client->last_submit_time;
	double spm = client->shares_per_minute;
	if(idle_ms > g_vardiff_retarget_ms && idle_ms > 0)
		spm = spm * (double)g_vardiff_retarget_ms / (double)idle_ms;
	if(g_vardiff_idle_ms > 0 && idle_ms > g_vardiff_idle_ms)
		spm = 0.0;

	double target_spm = g_vardiff_target_spm;
	if(target_spm < 1.0) target_spm = 1.0;
	double factor = spm / target_spm;

	// Only change if we are meaningfully off-target (deadband by variance).
	double newdiff = client->difficulty_actual;
	double up_th = 1.0 + max(0.0, g_vardiff_variance);
	double dn_th = 1.0 - max(0.0, g_vardiff_variance);
	if(factor > up_th)
		newdiff = client->difficulty_actual * min(g_vardiff_max_factor, factor);
	else if(factor < dn_th)
		newdiff = client->difficulty_actual * max(g_vardiff_min_factor, factor);
	else {
		client->last_vardiff_time = now;
		return;
	}

	if(g_debuglog_client)
		clientlog(client, "vardiff retarget spm=%.2f target=%.2f factor=%.2f diff %.6f -> %.6f idle=%lldms", spm, target_spm, factor, client->difficulty_actual, newdiff, idle_ms);

	client_change_difficulty(client, newdiff);
	client->last_vardiff_time = now;
}

int client_send_difficulty(YAAMP_CLIENT *client, double difficulty)
{
//	debuglog("%s diff %f\n", client->sock->ip, difficulty);
	client->shares_per_minute = YAAMP_SHAREPERSEC;

	if(difficulty >= 1)
		client_call(client, "mining.set_difficulty", "[%.0f]", difficulty);
	else
		client_call(client, "mining.set_difficulty", "[%0.8f]", difficulty);
	return 0;
}

void client_initialize_difficulty(YAAMP_CLIENT *client)
{
	char *p = strstr(client->password, "d=");
	char *p2 = strstr(client->password, "decred=");
	if(!p || p2) return;

	double diff = client_normalize_difficulty(atof(p+2));
	uint64_t user_target = diff_to_target(diff);

//	debuglog("%016llx target\n", user_target);
	if(user_target >= YAAMP_MINDIFF && user_target <= YAAMP_MAXDIFF)
	{
		client->difficulty_actual = diff;
		client->difficulty_fixed = true;
	}

}
