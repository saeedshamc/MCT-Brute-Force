/*
 * Copyright 2013 Gerhard Klostermeier
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


package de.syss.MifareClassicTool.Activities;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.Tag;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.appcompat.widget.AppCompatEditText;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import de.syss.MifareClassicTool.Common;
import de.syss.MifareClassicTool.MCReader;
import de.syss.MifareClassicTool.R;

/**
 * Brute force a numeric key range or a set of key files against a
 * MIFARE Classic tag and save the found keys to a key file.
 * Supports pausing, live progress, per-sector key type selection and
 * continuing the scan with a reconnected tag.
 */
public class BruteForce extends BasicActivity {

    private static final String LOG_TAG = BruteForce.class.getSimpleName();
    private static final String PREFS_NAME = "brute_force_settings";
    private static final int FILE_CHOOSER_KEY_FILES = 1;

    private static final int KEY_SOURCE_RANGE = 0;
    private static final int KEY_SOURCE_FILE = 1;

    private static final int SECTOR_MODE_ALL = 0;
    private static final int SECTOR_MODE_RANGE = 1;
    private static final int SECTOR_MODE_PICK = 2;

    private static final int RESUME_NONE = 0;
    private static final int RESUME_WAITING = 1;
    private static final int RESUME_RESUME = 2;
    private static final int RESUME_SAVE = 3;
    private static final int RESUME_DISCARD = 4;

    private RadioGroup mKeyTypeGroup;
    private RadioGroup mKeySourceGroup;
    private AppCompatEditText mKeyRangeFrom;
    private AppCompatEditText mKeyRangeTo;
    private AppCompatEditText mKeysPerSecond;
    private int mKeysPerSecondVal = 0;
    private LinearLayout mKeyRangeLayout;
    private LinearLayout mKeyFileLayout;
    private Button mChooseKeyFile;
    private TextView mKeyFileInfo;
    private final List<File> mKeyFiles = new ArrayList<>();
    private int mKeySource = KEY_SOURCE_RANGE;
    private RadioGroup mSectorModeGroup;
    private LinearLayout mSectorRangeLayout;
    private LinearLayout mSectorPickLayout;
    private final AppCompatCheckBox[] mSectorChecks = new AppCompatCheckBox[40];
    private final int[] mSectorKeyModes = new int[40];
    private AppCompatEditText mSectorFrom;
    private AppCompatEditText mSectorTo;
    private int mSectorMode = SECTOR_MODE_ALL;
    private int[] mSelectedSectors;
    private int[] mSelectedModes;
    private int mSectorTotal;
    private Button mStart;
    private Button mCancel;
    private Button mPause;
    private ProgressBar mProgressBar;
    private TextView mStatus;
    private TextView mKeyLog;

    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private volatile MCReader currentReader;
    private volatile boolean mIsRunning = false;
    private volatile boolean mPaused = false;
    private volatile boolean mCompletedNormally = false;
    private int mFirstSector = 0;
    private int mLastSector = -1;
    private int mAuthMode = MCReader.KEY_MAP_MODE_BOTH;
    private String mKeyRangeFromStr = "";
    private String mKeyRangeToStr = "";
    private File mOutputFile;

    private final List<Integer> mPendingSectors = new LinkedList<>();
    private List<Integer> mPendingModes;
    private final SparseArray<byte[][]> mFoundKeyMap = new SparseArray<>();
    private volatile int mFoundKeyCount = 0;
    private final Object mResumeLock = new Object();
    private int mResumeState = RESUME_NONE;

    private final Runnable mProgressUpdater = new Runnable() {
        @Override
        public void run() {
            if (!mIsRunning) {
                return;
            }
            updateProgressStatus();
            mHandler.postDelayed(this, 500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_brute_force);

        mKeyTypeGroup = findViewById(R.id.radioGroupBruteForceKeyType);
        mKeySourceGroup = findViewById(R.id.radioGroupBruteForceKeySource);
        mKeyRangeFrom = findViewById(R.id.editTextBruteForceKeyRangeFrom);
        mKeyRangeTo = findViewById(R.id.editTextBruteForceKeyRangeTo);
        mKeysPerSecond = findViewById(R.id.editTextBruteForceKeysPerSecond);
        mKeyRangeLayout = findViewById(R.id.linearLayoutBruteForceKeyRange);
        mKeyFileLayout = findViewById(R.id.linearLayoutBruteForceKeyFile);
        mChooseKeyFile = findViewById(R.id.buttonBruteForceChooseKeyFile);
        mKeyFileInfo = findViewById(R.id.textViewBruteForceKeyFiles);
        mSectorModeGroup = findViewById(R.id.radioGroupBruteForceSectorMode);
        mSectorRangeLayout = findViewById(R.id.linearLayoutBruteForceSectorRange);
        mSectorPickLayout = findViewById(R.id.linearLayoutBruteForceSectorPick);
        mSectorFrom = findViewById(R.id.editTextBruteForceSectorFrom);
        mSectorTo = findViewById(R.id.editTextBruteForceSectorTo);
        mStart = findViewById(R.id.buttonBruteForceStart);
        mCancel = findViewById(R.id.buttonBruteForceCancel);
        mPause = findViewById(R.id.buttonBruteForcePause);
        mProgressBar = findViewById(R.id.progressBarBruteForce);
        mStatus = findViewById(R.id.textViewBruteForceStatus);
        mKeyLog = findViewById(R.id.textViewBruteForceKeyLog);

        Arrays.fill(mSectorKeyModes, MCReader.KEY_MAP_MODE_BOTH);
        TextView hint = new TextView(this);
        hint.setText(R.string.text_sector_pick_hint);
        hint.setTextSize(12);
        mSectorPickLayout.addView(hint);
        for (int row = 0; row < 5; row++) {
            LinearLayout rowLayout = new LinearLayout(this);
            rowLayout.setOrientation(LinearLayout.HORIZONTAL);
            for (int col = 0; col < 8; col++) {
                final int sector = row * 8 + col;
                AppCompatCheckBox checkBox = new AppCompatCheckBox(this);
                checkBox.setText(String.valueOf(sector));
                LinearLayout.LayoutParams params =
                        new LinearLayout.LayoutParams(
                                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
                rowLayout.addView(checkBox, params);
                mSectorChecks[sector] = checkBox;
                checkBox.setOnLongClickListener(v -> {
                    cycleSectorKeyMode(sector);
                    return true;
                });
            }
            mSectorPickLayout.addView(rowLayout);
        }
        mKeyFileInfo.setOnLongClickListener(v -> {
            mKeyFiles.clear();
            updateKeyFileInfo();
            return true;
        });

        restoreSettings();
        mPause.setEnabled(false);
    }

    private void cycleSectorKeyMode(int sector) {
        int mode = mSectorKeyModes[sector];
        if (mode == MCReader.KEY_MAP_MODE_BOTH) {
            mode = MCReader.KEY_MAP_MODE_KEY_A;
        } else if (mode == MCReader.KEY_MAP_MODE_KEY_A) {
            mode = MCReader.KEY_MAP_MODE_KEY_B;
        } else {
            mode = MCReader.KEY_MAP_MODE_BOTH;
        }
        mSectorKeyModes[sector] = mode;
        updateSectorCheckText(mSectorChecks[sector], sector);
    }

    private void updateSectorCheckText(AppCompatCheckBox checkBox, int sector) {
        String suffix;
        if (mSectorKeyModes[sector] == MCReader.KEY_MAP_MODE_KEY_A) {
            suffix = "A";
        } else if (mSectorKeyModes[sector] == MCReader.KEY_MAP_MODE_KEY_B) {
            suffix = "B";
        } else {
            suffix = "";
        }
        checkBox.setText(sector + suffix);
    }

    public void onSectorModeChanged(View view) {
        mSectorMode = getSectorMode();
        mSectorRangeLayout.setVisibility(
                mSectorMode == SECTOR_MODE_RANGE ? View.VISIBLE : View.GONE);
        mSectorPickLayout.setVisibility(
                mSectorMode == SECTOR_MODE_PICK ? View.VISIBLE : View.GONE);
        mSectorFrom.setEnabled(mSectorMode == SECTOR_MODE_RANGE);
        mSectorTo.setEnabled(mSectorMode == SECTOR_MODE_RANGE);
    }

    private int getSectorMode() {
        int id = mSectorModeGroup.getCheckedRadioButtonId();
        if (id == R.id.radioButtonBruteForceSectorRange) {
            return SECTOR_MODE_RANGE;
        }
        if (id == R.id.radioButtonBruteForceSectorPick) {
            return SECTOR_MODE_PICK;
        }
        return SECTOR_MODE_ALL;
    }

    public void onKeySourceChanged(View view) {
        mKeySource = getKeySourceMode();
        mKeyRangeLayout.setVisibility(
                mKeySource == KEY_SOURCE_RANGE ? View.VISIBLE : View.GONE);
        mKeyFileLayout.setVisibility(
                mKeySource == KEY_SOURCE_FILE ? View.VISIBLE : View.GONE);
    }

    private int getKeySourceMode() {
        int id = mKeySourceGroup.getCheckedRadioButtonId();
        if (id == R.id.radioButtonBruteForceKeySourceFile) {
            return KEY_SOURCE_FILE;
        }
        return KEY_SOURCE_RANGE;
    }

    public void onChooseKeyFile(View view) {
        Intent intent = new Intent(this, FileChooser.class);
        intent.putExtra(FileChooser.EXTRA_DIR,
                Common.getFile(Common.KEYS_DIR).getAbsolutePath());
        intent.putExtra(FileChooser.EXTRA_TITLE,
                getString(R.string.text_open_key_file_title));
        intent.putExtra(FileChooser.EXTRA_BUTTON_TEXT,
                getString(R.string.action_choose_key_file));
        startActivityForResult(intent, FILE_CHOOSER_KEY_FILES);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode,
            Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_KEY_FILES
                && resultCode == Activity.RESULT_OK && data != null) {
            String path = data.getStringExtra(FileChooser.EXTRA_CHOSEN_FILE);
            if (path != null) {
                File file = new File(path);
                if (!mKeyFiles.contains(file)) {
                    mKeyFiles.add(file);
                }
                updateKeyFileInfo();
            }
        }
    }

    private void updateKeyFileInfo() {
        if (mKeyFiles.isEmpty()) {
            mKeyFileInfo.setText("");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (File file : mKeyFiles) {
            sb.append(file.getName()).append(", ");
        }
        sb.setLength(sb.length() - 2);
        mKeyFileInfo.setText(getString(R.string.text_key_files_selected,
                mKeyFiles.size()) + " " + sb);
    }

    private void collectSectorSelection() {
        int count = 0;
        for (AppCompatCheckBox checkBox : mSectorChecks) {
            if (checkBox.isChecked()) {
                count++;
            }
        }
        mSelectedSectors = new int[count];
        mSelectedModes = new int[count];
        count = 0;
        for (int i = 0; i < mSectorChecks.length; i++) {
            if (mSectorChecks[i].isChecked()) {
                mSelectedSectors[count] = i;
                mSelectedModes[count] = mSectorKeyModes[i];
                count++;
            }
        }
    }

    private int getSelectedKeyMapAuthMode() {
        int checkedId = mKeyTypeGroup.getCheckedRadioButtonId();
        if (checkedId == R.id.radioButtonBruteForceKeyTypeA) {
            return MCReader.KEY_MAP_MODE_KEY_A;
        } else if (checkedId == R.id.radioButtonBruteForceKeyTypeB) {
            return MCReader.KEY_MAP_MODE_KEY_B;
        }
        return MCReader.KEY_MAP_MODE_BOTH;
    }

    public void onStartBruteForce(View view) {
        if (mIsRunning) {
            return;
        }
        mKeyRangeFromStr = mKeyRangeFrom.getText().toString().trim();
        mKeyRangeToStr = mKeyRangeTo.getText().toString().trim();
        mKeySource = getKeySourceMode();
        mSectorMode = getSectorMode();
        mAuthMode = getSelectedKeyMapAuthMode();
        mKeysPerSecondVal = parseKeysPerSecondLocal(
                mKeysPerSecond.getText().toString());
        if (mKeysPerSecondVal < 0) {
            Toast.makeText(this, R.string.info_invalid_key_range,
                    Toast.LENGTH_LONG).show();
            return;
        }

        if (mKeySource == KEY_SOURCE_FILE && mKeyFiles.isEmpty()) {
            Toast.makeText(this, R.string.info_select_key_file,
                    Toast.LENGTH_LONG).show();
            return;
        }
        if (mKeySource == KEY_SOURCE_RANGE) {
            long rangeFrom = parseKeyHexLocal(mKeyRangeFromStr);
            long rangeTo = parseKeyHexLocal(mKeyRangeToStr);
            if (rangeFrom < 0 || rangeTo < rangeFrom) {
                Toast.makeText(this, R.string.info_invalid_key_range,
                        Toast.LENGTH_LONG).show();
                return;
            }
        }

        mSelectedSectors = null;
        mSelectedModes = null;
        if (mSectorMode == SECTOR_MODE_RANGE) {
            int from = parseSectorLocal(mSectorFrom.getText().toString());
            int to = parseSectorLocal(mSectorTo.getText().toString());
            if (from < 0 || to < from) {
                Toast.makeText(this, R.string.info_invalid_sector_range,
                        Toast.LENGTH_LONG).show();
                return;
            }
            mFirstSector = from;
            mLastSector = to;
        } else if (mSectorMode == SECTOR_MODE_PICK) {
            collectSectorSelection();
            if (mSelectedSectors.length == 0) {
                Toast.makeText(this, R.string.info_invalid_sector_range,
                        Toast.LENGTH_LONG).show();
                return;
            }
            mFirstSector = mSelectedSectors[0];
            mLastSector = mSelectedSectors[mSelectedSectors.length - 1];
        } else {
            mFirstSector = 0;
            mLastSector = -1;
        }
        saveSettings();
        showSaveFileDialog();
    }

    private void showSaveFileDialog() {
        final EditText input = new EditText(this);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        input.setText("new");
        input.setSelectAllOnFocus(true);
        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_save_keys_title)
                .setMessage(R.string.dialog_save_keys)
                .setView(input)
                .setPositiveButton(R.string.action_start,
                        (dialog, which) -> {
                            String name = input.getText().toString().trim();
                            mOutputFile = getUniqueKeyFile(name);
                            startBruteForce();
                        })
                .setNegativeButton(R.string.action_cancel, null)
                .show();
    }

    private File getUniqueKeyFile(String baseName) {
        baseName = baseName.trim();
        if (baseName.isEmpty()) {
            baseName = "new";
        }
        baseName = baseName.replaceAll("[^A-Za-z0-9_\\-]", "_");
        if (baseName.isEmpty()) {
            baseName = "new";
        }
        if (baseName.toLowerCase(Locale.US).endsWith(".keys")) {
            baseName = baseName.substring(0, baseName.length() - 5);
        }
        File dir = Common.getFile(Common.KEYS_DIR);
        for (int i = 0; ; i++) {
            String name = i == 0 ? baseName : baseName + i;
            File file = new File(dir, name + ".keys");
            if (!file.exists()) {
                return file;
            }
        }
    }

    private void buildPendingSectorList(int sectorCount) {
        mPendingSectors.clear();
        mPendingModes = null;
        if (mSectorMode == SECTOR_MODE_ALL) {
            for (int i = 0; i < sectorCount; i++) {
                mPendingSectors.add(i);
            }
        } else if (mSectorMode == SECTOR_MODE_RANGE) {
            for (int i = mFirstSector; i <= mLastSector; i++) {
                mPendingSectors.add(i);
            }
        } else {
            for (int i = 0; i < mSelectedSectors.length; i++) {
                mPendingSectors.add(mSelectedSectors[i]);
            }
            mPendingModes = new ArrayList<>();
            for (int mode : mSelectedModes) {
                mPendingModes.add(mode);
            }
        }
        mSectorTotal = mPendingSectors.size();
    }

    private int[] pendingSectorsArray() {
        int[] sectors = new int[mPendingSectors.size()];
        for (int i = 0; i < sectors.length; i++) {
            sectors[i] = mPendingSectors.get(i);
        }
        return sectors;
    }

    private int[] pendingModesArray() {
        if (mPendingModes == null) {
            return null;
        }
        int[] modes = new int[mPendingModes.size()];
        for (int i = 0; i < modes.length; i++) {
            modes[i] = mPendingModes.get(i);
        }
        return modes;
    }

    private boolean configureReaderForPending(MCReader reader) {
        if (mKeySource == KEY_SOURCE_FILE) {
            int loaded = reader.setKeyFile(
                    mKeyFiles.toArray(new File[0]), this);
            if (loaded <= 0) {
                return false;
            }
        } else if (!reader.setKeyRange(mKeyRangeFromStr, mKeyRangeToStr)) {
            return false;
        }
        reader.setKeyMapAuthMode(mAuthMode);
        reader.setKeyMapKeysPerSecond(mKeysPerSecondVal);
        return reader.setMappingSectors(pendingSectorsArray(),
                pendingModesArray());
    }

    private void startBruteForce() {
        MCReader reader = Common.checkForTagAndCreateReader(this);
        currentReader = reader;
        if (reader == null) {
            return;
        }
        buildPendingSectorList(reader.getSectorCount());
        if (mPendingSectors.isEmpty()
                || !configureReaderForPending(reader)) {
            Toast.makeText(this, R.string.info_mapping_sector_out_of_range,
                    Toast.LENGTH_LONG).show();
            reader.close();
            currentReader = null;
            return;
        }

        getWindow().addFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        mFoundKeyMap.clear();
        mFoundKeyCount = 0;
        mKeyLog.setText("");
        mCompletedNormally = false;
        mPaused = false;
        mProgressBar.setMax(mSectorTotal);
        mProgressBar.setProgress(0);
        mStatus.setText("");
        mStart.setEnabled(false);
        mPause.setEnabled(true);
        mPause.setText(R.string.action_pause);
        mIsRunning = true;
        mHandler.post(mProgressUpdater);
        createBruteForceKeyMap(reader);
    }

    private void createBruteForceKeyMap(MCReader reader) {
        new Thread(() -> {
            MCReader r = reader;
            while (mIsRunning && !mPendingSectors.isEmpty()) {
                while (mPaused && mIsRunning) {
                    sleepQuietly(200);
                }
                if (!mIsRunning) {
                    break;
                }
                int sector = r.buildNextKeyMapPart();
                if (sector == -1) {
                    if (!mIsRunning) {
                        break;
                    }
                    mHandler.post(this::showTagLostDialog);
                    waitForResumeDecision();
                    if (!mIsRunning) {
                        break;
                    }
                    if (mResumeState == RESUME_SAVE) {
                        mHandler.post(this::saveFoundKeysAndFinish);
                        return;
                    }
                    if (mResumeState == RESUME_DISCARD) {
                        mHandler.post(this::finishWithoutSaving);
                        return;
                    }
                    MCReader newReader = waitForTagReader();
                    if (newReader == null) {
                        mHandler.post(this::finishWithoutSaving);
                        return;
                    }
                    try {
                        r.close();
                    } catch (Exception e) {
                        // Do nothing.
                    }
                    if (!configureReaderForPending(newReader)) {
                        newReader.close();
                        mHandler.post(this::finishWithoutSaving);
                        return;
                    }
                    r = newReader;
                    currentReader = newReader;
                    mResumeState = RESUME_NONE;
                    mPaused = false;
                    r.setKeyMapPaused(false);
                } else {
                    synchronized (mPendingSectors) {
                        if (!mPendingSectors.isEmpty()) {
                            mPendingSectors.remove(0);
                        }
                        if (mPendingModes != null && !mPendingModes.isEmpty()) {
                            mPendingModes.remove(0);
                        }
                    }
                    mergeFoundKeys(r, sector);
                    final int done;
                    synchronized (mPendingSectors) {
                        done = mSectorTotal - mPendingSectors.size();
                    }
                    mHandler.post(() -> mProgressBar.setProgress(done));
                }
            }
            if (mIsRunning && mPendingSectors.isEmpty()) {
                mCompletedNormally = true;
            }
            mHandler.post(this::finishBruteForce);
        }).start();
    }

    private void mergeFoundKeys(MCReader reader, int sector) {
        SparseArray<byte[][]> keyMap = reader.getKeyMap();
        if (keyMap == null) {
            return;
        }
        int index = keyMap.indexOfKey(sector);
        if (index < 0) {
            return;
        }
        final byte[][] keys = keyMap.valueAt(index);
        synchronized (mFoundKeyMap) {
            mFoundKeyMap.put(sector, keys);
        }
        recountFoundKeys();
        mHandler.post(() -> appendKeyLogEntry(sector, keys));
    }

    private void recountFoundKeys() {
        Set<String> unique = new LinkedHashSet<>();
        synchronized (mFoundKeyMap) {
            for (int i = 0; i < mFoundKeyMap.size(); i++) {
                byte[][] pair = mFoundKeyMap.valueAt(i);
                if (pair != null) {
                    if (pair[0] != null) {
                        unique.add(Common.bytes2Hex(pair[0]));
                    }
                    if (pair[1] != null) {
                        unique.add(Common.bytes2Hex(pair[1]));
                    }
                }
            }
        }
        mFoundKeyCount = unique.size();
    }

    private void appendKeyLogEntry(int sector, byte[][] keys) {
        if (keys == null) {
            return;
        }
        String keyA = keys[0] != null
                ? Common.bytes2Hex(keys[0]) : MCReader.NO_KEY;
        String keyB = keys[1] != null
                ? Common.bytes2Hex(keys[1]) : MCReader.NO_KEY;
        mKeyLog.append(getString(R.string.text_key_log_line,
                sector, keyA, keyB));
        mKeyLog.append("\n");
    }

    private void updateProgressStatus() {
        int done;
        synchronized (mPendingSectors) {
            done = mSectorTotal - mPendingSectors.size();
        }
        MCReader reader = currentReader;
        String progress = "";
        if (reader != null) {
            int sector = reader.getKeyMapProgressSector();
            long keyIndex = reader.getKeyMapProgressKey();
            long keyTotal = reader.getKeyMapProgressKeyTotal();
            if (sector >= 0 && keyTotal > 0) {
                progress = getString(R.string.info_brute_force_progress,
                        sector, done, mSectorTotal,
                        keyIndex < 0 ? 0 : keyIndex + 1, keyTotal,
                        mFoundKeyCount);
            }
        }
        if (mPaused) {
            mStatus.setText(getString(R.string.info_brute_force_paused)
                    + (progress.isEmpty() ? "" : " — " + progress));
        } else {
            mStatus.setText(progress);
        }
    }

    private void waitForResumeDecision() {
        synchronized (mResumeLock) {
            mResumeState = RESUME_WAITING;
            while (mResumeState == RESUME_WAITING && mIsRunning) {
                try {
                    mResumeLock.wait();
                } catch (InterruptedException e) {
                    // Do nothing.
                }
            }
        }
    }

    private void onResumeDecision(int state) {
        synchronized (mResumeLock) {
            mResumeState = state;
            mResumeLock.notifyAll();
        }
    }

    private void showTagLostDialog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_tag_lost_title)
                .setMessage(getString(R.string.dialog_tag_lost_message,
                        mFoundKeyCount))
                .setPositiveButton(R.string.action_resume_scan,
                        (dialog, which) -> onResumeDecision(RESUME_RESUME))
                .setNeutralButton(R.string.action_save_keys,
                        (dialog, which) -> onResumeDecision(RESUME_SAVE))
                .setNegativeButton(R.string.action_discard,
                        (dialog, which) -> onResumeDecision(RESUME_DISCARD))
                .setCancelable(false)
                .show();
    }

    private MCReader waitForTagReader() {
        while (mIsRunning) {
            MCReader reader = null;
            Tag tag = Common.getTag();
            if (tag != null) {
                try {
                    reader = MCReader.get(tag);
                } catch (Exception e) {
                    reader = null;
                }
            }
            if (reader != null) {
                try {
                    reader.connect();
                } catch (Exception e) {
                    // Retry below.
                }
                if (reader.isConnected()) {
                    return reader;
                }
                reader.close();
            }
            sleepQuietly(500);
        }
        return null;
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            // Do nothing.
        }
    }

    private void finishBruteForce() {
        getWindow().clearFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        mProgressBar.setProgress(0);
        mStatus.setText("");
        mStart.setEnabled(true);
        mPause.setEnabled(false);
        mPause.setText(R.string.action_pause);
        MCReader reader = currentReader;
        currentReader = null;
        if (reader != null) {
            reader.close();
        }
        boolean wasRunning = mIsRunning;
        mIsRunning = false;
        mPaused = false;
        synchronized (mPendingSectors) {
            mPendingSectors.clear();
        }
        if (mPendingModes != null) {
            mPendingModes.clear();
        }
        if (wasRunning && mCompletedNormally) {
            showBruteForceResults();
        }
    }

    private void saveFoundKeysAndFinish() {
        finishBruteForce();
        showBruteForceResults();
    }

    private void finishWithoutSaving() {
        mIsRunning = false;
        finishBruteForce();
    }

    private void showBruteForceResults() {
        Set<String> keys = new LinkedHashSet<>();
        synchronized (mFoundKeyMap) {
            for (int i = 0; i < mFoundKeyMap.size(); i++) {
                byte[][] pair = mFoundKeyMap.valueAt(i);
                if (pair != null) {
                    if (pair[0] != null) {
                        keys.add(Common.bytes2Hex(pair[0]));
                    }
                    if (pair[1] != null) {
                        keys.add(Common.bytes2Hex(pair[1]));
                    }
                }
            }
        }
        if (keys.isEmpty() || mOutputFile == null) {
            Toast.makeText(this, R.string.info_brute_force_no_keys,
                    Toast.LENGTH_LONG).show();
            return;
        }
        boolean saved = Common.saveFile(mOutputFile,
                keys.toArray(new String[0]), false);
        String title = saved
                ? getString(R.string.info_bruteforce_keys_saved,
                        keys.size(), mOutputFile.getName())
                : getString(R.string.info_strange_error);
        showBruteForceResultsDialog(keys, title);
    }

    private void showBruteForceResultsDialog(Set<String> keys, String title) {
        StringBuilder sb = new StringBuilder();
        for (String key : keys) {
            sb.append(key).append('\n');
        }
        TextView tv = new TextView(this);
        tv.setTextIsSelectable(true);
        tv.setText(sb.toString());
        int pad = Common.dpToPx(16);
        tv.setPadding(pad, pad, pad, pad);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(sv)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    public void onPauseBruteForce(View view) {
        if (!mIsRunning) {
            return;
        }
        mPaused = !mPaused;
        mPause.setText(mPaused ? R.string.action_resume
                : R.string.action_pause);
        MCReader reader = currentReader;
        if (reader != null) {
            reader.setKeyMapPaused(mPaused);
        }
        updateProgressStatus();
    }

    public void onCancelBruteForce(View view) {
        if (mIsRunning) {
            mIsRunning = false;
            mPaused = false;
            synchronized (mResumeLock) {
                mResumeState = RESUME_DISCARD;
                mResumeLock.notifyAll();
            }
            MCReader reader = currentReader;
            if (reader != null) {
                reader.setKeyMapPaused(false);
                reader.cancelCreateKeyMap();
            }
            mStatus.setText("");
        } else {
            finish();
        }
    }

    @Override
    public void onBackPressed() {
        if (mIsRunning) {
            onCancelBruteForce(null);
        } else {
            super.onBackPressed();
        }
    }

    private void saveSettings() {
        SharedPreferences prefs =
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("keyFrom", mKeyRangeFromStr);
        editor.putString("keyTo", mKeyRangeToStr);
        editor.putInt("authMode", mAuthMode);
        editor.putInt("keySource", mKeySource);
        editor.putInt("sectorMode", mSectorMode);
        editor.putInt("keysPerSecond", mKeysPerSecondVal);
        editor.putInt("sectorFrom", mFirstSector);
        editor.putInt("sectorTo", mLastSector);
        long mask = 0;
        StringBuilder modes = new StringBuilder();
        for (int i = 0; i < mSectorChecks.length; i++) {
            modes.append((char) ('0' + mSectorKeyModes[i]));
            if (mSectorChecks[i].isChecked()) {
                mask |= 1L << i;
            }
        }
        editor.putLong("pickMask", mask);
        editor.putString("sectorModes", modes.toString());
        editor.apply();
    }

    private void restoreSettings() {
        SharedPreferences prefs =
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        mKeyRangeFromStr = prefs.getString("keyFrom", "");
        mKeyRangeToStr = prefs.getString("keyTo", "");
        mKeyRangeFrom.setText(mKeyRangeFromStr);
        mKeyRangeTo.setText(mKeyRangeToStr);
        mAuthMode = prefs.getInt("authMode", MCReader.KEY_MAP_MODE_BOTH);
        int authId = R.id.radioButtonBruteForceKeyTypeBoth;
        if (mAuthMode == MCReader.KEY_MAP_MODE_KEY_A) {
            authId = R.id.radioButtonBruteForceKeyTypeA;
        } else if (mAuthMode == MCReader.KEY_MAP_MODE_KEY_B) {
            authId = R.id.radioButtonBruteForceKeyTypeB;
        }
        ((RadioButton) findViewById(authId)).setChecked(true);

        mKeySource = prefs.getInt("keySource", KEY_SOURCE_RANGE);
        int sourceId = mKeySource == KEY_SOURCE_FILE
                ? R.id.radioButtonBruteForceKeySourceFile
                : R.id.radioButtonBruteForceKeySourceRange;
        ((RadioButton) findViewById(sourceId)).setChecked(true);
        onKeySourceChanged(null);

        mSectorMode = prefs.getInt("sectorMode", SECTOR_MODE_ALL);
        int sectorId = R.id.radioButtonBruteForceSectorAll;
        if (mSectorMode == SECTOR_MODE_RANGE) {
            sectorId = R.id.radioButtonBruteForceSectorRange;
        } else if (mSectorMode == SECTOR_MODE_PICK) {
            sectorId = R.id.radioButtonBruteForceSectorPick;
        }
        ((RadioButton) findViewById(sectorId)).setChecked(true);
        onSectorModeChanged(null);

        mKeysPerSecondVal = prefs.getInt("keysPerSecond", 0);
        if (mKeysPerSecondVal > 0) {
            mKeysPerSecond.setText(String.valueOf(mKeysPerSecondVal));
        }
        mSectorFrom.setText(String.valueOf(prefs.getInt("sectorFrom", 0)));
        mSectorTo.setText(String.valueOf(prefs.getInt("sectorTo", 0)));

        long mask = prefs.getLong("pickMask", 0);
        String modes = prefs.getString("sectorModes", "");
        for (int i = 0; i < mSectorChecks.length; i++) {
            mSectorChecks[i].setChecked((mask & (1L << i)) != 0);
            if (i < modes.length()) {
                char c = modes.charAt(i);
                if (c >= '0' && c <= '2') {
                    mSectorKeyModes[i] = c - '0';
                }
            }
            updateSectorCheckText(mSectorChecks[i], i);
        }
    }

    private static long parseKeyHexLocal(String hex) {
        if (hex == null) {
            return -1;
        }
        hex = hex.trim();
        if (hex.isEmpty() || hex.length() > 12
                || !hex.matches("[0-9A-Fa-f]+")) {
            return -1;
        }
        try {
            return Long.parseLong(hex, 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static int parseKeysPerSecondLocal(String text) {
        if (text == null || text.trim().isEmpty()) {
            return 0;
        }
        try {
            int value = Integer.parseInt(text.trim());
            return value >= 0 ? value : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static int parseSectorLocal(String text) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Exception e) {
            return -1;
        }
    }
}
